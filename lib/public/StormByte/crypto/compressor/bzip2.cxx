#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/buffer/producer.hxx>

#include <algorithm>
#include <bzlib.h>
#include <cstring>
#include <thread>
#include <iostream>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto::Compressor;

Bzip2::Bzip2(unsigned short level):
	Generic(Type::Bzip2, std::clamp<unsigned short>(static_cast<unsigned short>(level), 1, 9)) {}

bool Bzip2::DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	if (input.size_bytes() == 0) {
		return true;
	}

	try {
		// Calculate an upper bound for compressed data size per bzip2 docs
		unsigned int inLen = static_cast<unsigned int>(input.size_bytes());
		unsigned int outLen = inLen + (inLen / 100) + 600; // recommended extra
		std::vector<char> outBuf(outLen);

		int rc = BZ2_bzBuffToBuffCompress(
			outBuf.data(),
			&outLen,
			reinterpret_cast<char*>(const_cast<std::byte*>(input.data())),
			inLen,
			static_cast<int>(m_level),
			0, // verbosity
			30 // workFactor
		);

		if (rc != BZ_OK) {
			return false;
		}

		// Move into DataType and write
		DataType compressed;
		compressed.resize(outLen);
		std::memcpy(compressed.data(), reinterpret_cast<const std::byte*>(outBuf.data()), outLen);
		output.Write(std::move(compressed));
		return true;
	} catch (...) {
		return false;
	}
}

Consumer Bzip2::DoCompress(Consumer consumer, ReadMode mode) const noexcept {
	Producer producer;

	std::thread([consumer, producer, mode, level = m_level]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			DataType outBuffer;

			bz_stream strm{};
			int rc = BZ2_bzCompressInit(&strm, static_cast<int>(level), 0, 30);
			if (rc != BZ_OK) {
				producer.SetError();
				return;
			}

			std::vector<char> inData;
			std::vector<char> outChunk(chunkSize);

			while (!consumer.EoF()) {
				size_t available = consumer.AvailableBytes();
				if (available == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t toRead = std::min(available, chunkSize);
				DataType data;
				bool ok;
				if (mode == ReadMode::Copy)
					ok = consumer.Read(toRead, data);
				else
					ok = consumer.Extract(toRead, data);
				if (!ok) {
					BZ2_bzCompressEnd(&strm);
					producer.SetError();
					return;
				}

				// prepare stream
				strm.next_in = reinterpret_cast<char*>(data.data());
				strm.avail_in = static_cast<unsigned int>(data.size());

				int action = BZ_RUN;
				while (strm.avail_in > 0) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					rc = BZ2_bzCompress(&strm, action);
					if (rc != BZ_RUN_OK && rc != BZ_FINISH_OK && rc != BZ_FLUSH_OK) {
						BZ2_bzCompressEnd(&strm);
						producer.SetError();
						return;
					}

					unsigned int produced = static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced) {
						DataType part(produced);
						std::memcpy(part.data(), reinterpret_cast<const std::byte*>(outChunk.data()), produced);
						if (!producer.Write(std::move(part))) {
							BZ2_bzCompressEnd(&strm);
							producer.SetError();
							return;
						}
					}
				}
			}

			// Finish
			for (;;) {
				strm.next_out = outChunk.data();
				strm.avail_out = static_cast<unsigned int>(outChunk.size());
				int r = BZ2_bzCompress(&strm, BZ_FINISH);
				if (r != BZ_FINISH_OK && r != BZ_STREAM_END && r != BZ_RUN_OK) {
					BZ2_bzCompressEnd(&strm);
					producer.SetError();
					return;
				}
				unsigned int produced = static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
				if (produced) {
					DataType part(produced);
					std::memcpy(part.data(), reinterpret_cast<const std::byte*>(outChunk.data()), produced);
					if (!producer.Write(std::move(part))) {
						BZ2_bzCompressEnd(&strm);
						producer.SetError();
						return;
					}
				}
				if (r == BZ_STREAM_END) break;
			}

			BZ2_bzCompressEnd(&strm);
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

bool Bzip2::DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	if (input.size_bytes() == 0) {
		return true;
	}

	try {
		unsigned int inLen = static_cast<unsigned int>(input.size_bytes());
		unsigned int outLen = inLen * 5 + 1000; // heuristic; decompressed may be larger
		std::vector<char> outBuf(outLen);

		int rc = BZ2_bzBuffToBuffDecompress(
			outBuf.data(),
			&outLen,
			reinterpret_cast<char*>(const_cast<std::byte*>(input.data())),
			inLen,
			0, // small
			0  // verbosity
		);

		if (rc != BZ_OK) {
			return false;
		}

		DataType decompressed;
		decompressed.resize(outLen);
		std::memcpy(decompressed.data(), reinterpret_cast<const std::byte*>(outBuf.data()), outLen);
		output.Write(std::move(decompressed));
		return true;
	} catch (...) {
		return false;
	}
}

Consumer Bzip2::DoDecompress(Consumer consumer, ReadMode mode) const noexcept {
	Producer producer;

	std::thread([consumer, producer, mode]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			DataType outBuffer;

			bz_stream strm{};
			int rc = BZ2_bzDecompressInit(&strm, 0, 0);
			if (rc != BZ_OK) {
				producer.SetError();
				return;
			}

			std::vector<char> outChunk(chunkSize);

			while (!consumer.EoF()) {
				size_t available = consumer.AvailableBytes();
				if (available == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t toRead = std::min(available, chunkSize);
				DataType data;
				bool ok;
				if (mode == ReadMode::Copy)
					ok = consumer.Read(toRead, data);
				else
					ok = consumer.Extract(toRead, data);
				if (!ok) {
					BZ2_bzDecompressEnd(&strm);
					producer.SetError();
					return;
				}

				strm.next_in = reinterpret_cast<char*>(data.data());
				strm.avail_in = static_cast<unsigned int>(data.size());

				while (strm.avail_in > 0) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					int r = BZ2_bzDecompress(&strm);
					if (r != BZ_OK && r != BZ_STREAM_END) {
						BZ2_bzDecompressEnd(&strm);
						producer.SetError();
						return;
					}

					unsigned int produced = static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced) {
						DataType part(produced);
						std::memcpy(part.data(), reinterpret_cast<const std::byte*>(outChunk.data()), produced);
						if (!producer.Write(std::move(part))) {
							BZ2_bzDecompressEnd(&strm);
							producer.SetError();
							return;
						}
					}
					if (r == BZ_STREAM_END) break;
				}
			}

			BZ2_bzDecompressEnd(&strm);
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}