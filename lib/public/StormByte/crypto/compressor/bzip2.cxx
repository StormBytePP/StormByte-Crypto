#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/crypto/implementation/compressor/details.hxx>
#include <StormByte/buffer/producer.hxx>

#include <algorithm>
#include <bzlib.h>
#include <cstring>
#include <memory>
#include <vector>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using namespace StormByte::Crypto::Compressor;

namespace {
	constexpr size_t kOutChunk = 4096;

	struct Bzip2CompressOps final : StormByte::Crypto::Implementation::Compressor::StreamOps {
		bz_stream strm{};
		std::vector<char> outChunk;
		bool ok = false;

		explicit Bzip2CompressOps(unsigned short level)
			: outChunk(kOutChunk)
		{
			int rc = BZ2_bzCompressInit(&strm, static_cast<int>(level), 0, 30);
			ok = (rc == BZ_OK);
		}

		~Bzip2CompressOps() override
		{
			if (ok)
				BZ2_bzCompressEnd(&strm);
		}

		bool Process(std::span<const std::byte> in, DataType& out) override
		{
			if (!ok)
				return false;
			try {
				strm.next_in = reinterpret_cast<char*>(
					const_cast<std::byte*>(in.data()));
				strm.avail_in = static_cast<unsigned int>(in.size_bytes());

				while (strm.avail_in > 0) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					int rc = BZ2_bzCompress(&strm, BZ_RUN);
					if (rc != BZ_RUN_OK && rc != BZ_FINISH_OK && rc != BZ_FLUSH_OK)
						return false;

					unsigned int produced =
						static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced) {
						size_t old = out.size();
						out.resize(old + produced);
						std::memcpy(out.data() + old,
									reinterpret_cast<const std::byte*>(outChunk.data()),
									produced);
					}
				}
				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(DataType& out) override
		{
			if (!ok)
				return false;
			try {
				for (;;) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					int r = BZ2_bzCompress(&strm, BZ_FINISH);
					if (r != BZ_FINISH_OK && r != BZ_STREAM_END && r != BZ_RUN_OK)
						return false;

					unsigned int produced =
						static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced) {
						size_t old = out.size();
						out.resize(old + produced);
						std::memcpy(out.data() + old,
									reinterpret_cast<const std::byte*>(outChunk.data()),
									produced);
					}
					if (r == BZ_STREAM_END)
						break;
				}
				BZ2_bzCompressEnd(&strm);
				ok = false; // already ended
				return true;
			} catch (...) {
				return false;
			}
		}
	};

	struct Bzip2DecompressOps final : StormByte::Crypto::Implementation::Compressor::StreamOps {
		bz_stream strm{};
		std::vector<char> outChunk;
		bool ok = false;
		bool ended = false;

		Bzip2DecompressOps()
			: outChunk(kOutChunk)
		{
			int rc = BZ2_bzDecompressInit(&strm, 0, 0);
			ok = (rc == BZ_OK);
		}

		~Bzip2DecompressOps() override
		{
			if (ok)
				BZ2_bzDecompressEnd(&strm);
		}

		bool Process(std::span<const std::byte> in, DataType& out) override
		{
			if (!ok || ended)
				return !ended; // already finished is ok
			try {
				strm.next_in = reinterpret_cast<char*>(
					const_cast<std::byte*>(in.data()));
				strm.avail_in = static_cast<unsigned int>(in.size_bytes());

				while (strm.avail_in > 0) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					int r = BZ2_bzDecompress(&strm);
					if (r != BZ_OK && r != BZ_STREAM_END)
						return false;

					unsigned int produced =
						static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced) {
						size_t old = out.size();
						out.resize(old + produced);
						std::memcpy(out.data() + old,
									reinterpret_cast<const std::byte*>(outChunk.data()),
									produced);
					}
					if (r == BZ_STREAM_END) {
						ended = true;
						break;
					}
				}
				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(DataType& /*out*/) override
		{
			if (!ok)
				return false;
			BZ2_bzDecompressEnd(&strm);
			ok = false;
			return true;
		}
	};
}

Bzip2::Bzip2(unsigned short level)
	: Generic(Type::Bzip2,
			std::clamp<unsigned short>(static_cast<unsigned short>(level), 1, 9))
{}

bool Bzip2::DoCompress(std::span<const std::byte> input, WriteOnly& output) const noexcept
{
	// Keep one-shot BuffToBuff path (original): empty input is success
	if (input.size_bytes() == 0)
		return true;

	try {
		unsigned int inLen = static_cast<unsigned int>(input.size_bytes());
		unsigned int outLen = inLen + (inLen / 100) + 600;
		std::vector<char> outBuf(outLen);

		int rc = BZ2_bzBuffToBuffCompress(
			outBuf.data(),
			&outLen,
			reinterpret_cast<char*>(const_cast<std::byte*>(input.data())),
			inLen,
			static_cast<int>(m_level),
			0,
			30
		);
		if (rc != BZ_OK)
			return false;

		DataType compressed;
		compressed.resize(outLen);
		std::memcpy(compressed.data(),
					reinterpret_cast<const std::byte*>(outBuf.data()),
					outLen);
		return output.Write(std::move(compressed));
	} catch (...) {
		return false;
	}
}

Consumer Bzip2::DoCompress(Consumer consumer, ReadMode mode) const noexcept
{
	return Implementation::Compressor::Stream(
		std::move(consumer), mode, std::make_unique<Bzip2CompressOps>(m_level));
}

bool Bzip2::DoDecompress(std::span<const std::byte> input, WriteOnly& output) const noexcept
{
	if (input.size_bytes() == 0)
		return true;

	try {
		unsigned int inLen = static_cast<unsigned int>(input.size_bytes());
		unsigned int outLen = inLen * 5 + 1000;
		std::vector<char> outBuf(outLen);

		int rc = BZ2_bzBuffToBuffDecompress(
			outBuf.data(),
			&outLen,
			reinterpret_cast<char*>(const_cast<std::byte*>(input.data())),
			inLen,
			0,
			0
		);
		if (rc != BZ_OK)
			return false;

		DataType decompressed;
		decompressed.resize(outLen);
		std::memcpy(decompressed.data(),
					reinterpret_cast<const std::byte*>(outBuf.data()),
					outLen);
		return output.Write(std::move(decompressed));
	} catch (...) {
		return false;
	}
}

Consumer Bzip2::DoDecompress(Consumer consumer, ReadMode mode) const noexcept
{
	return Implementation::Compressor::Stream(
		std::move(consumer), mode, std::make_unique<Bzip2DecompressOps>());
}
