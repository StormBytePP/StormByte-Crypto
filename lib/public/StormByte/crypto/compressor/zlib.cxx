#include <StormByte/crypto/compressor/zlib.hxx>
#include <StormByte/buffer/producer.hxx>

#include <algorithm>
#include <filters.h>
#include <thread>
#include <zlib.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto::Compressor;

Zlib::Zlib(unsigned short level):
	Generic(Type::Zlib, std::clamp<unsigned short>(static_cast<unsigned short>(level), 1, CryptoPP::ZlibCompressor::MAX_DEFLATE_LEVEL)) {}

bool Zlib::DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	try {
		DataType compressedBuffer;

		// Use Crypto++'s Zlib for compression (Deflate) with VectorSink writing into DataType
		CryptoPP::StringSource ss(
			reinterpret_cast<const uint8_t*>(input.data()),
			input.size_bytes(),
			true,
			new CryptoPP::ZlibCompressor(
				new CryptoPP::StringSinkTemplate<DataType>(compressedBuffer),
				m_level
			)
		);

		// Move compressed DataType into output
		output.Write(std::move(compressedBuffer));
		return true;
	}
	catch (const CryptoPP::Exception& e) {
		return false;
	}
}

Consumer Zlib::DoCompress(Consumer consumer, ReadMode mode) const noexcept {
	Producer producer;

	std::thread([consumer, producer, mode, level = m_level]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			DataType compressedBuffer;
			CryptoPP::ZlibCompressor compressor(
				new CryptoPP::StringSinkTemplate<DataType>(compressedBuffer),
				level
			);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				bool read_ok;
				if (mode == ReadMode::Copy)
					read_ok = consumer.Read(bytesToRead, data);
				else
					read_ok = consumer.Extract(bytesToRead, data);
				if (!read_ok) {
					producer.SetError();
					return;
				}

				compressor.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
				compressor.Flush(true);
				if (!compressedBuffer.empty()) {
					(void)producer.Write(std::move(compressedBuffer));
					compressedBuffer.clear();
				}
			}
			compressor.MessageEnd();
			if (!compressedBuffer.empty()) {
				(void)producer.Write(std::move(compressedBuffer));
			}
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

bool Zlib::DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	try {
		DataType decompressedBuffer;

		// Use Crypto++'s Zlib for decompression (Inflate) with StringSinkTemplate
		CryptoPP::StringSource ss(
			reinterpret_cast<const uint8_t*>(input.data()),
			input.size_bytes(),
			true,
			new CryptoPP::ZlibDecompressor(
				new CryptoPP::StringSinkTemplate<DataType>(decompressedBuffer)
			)
		);

		output.Write(std::move(decompressedBuffer));
		return true;
	}
	catch (const CryptoPP::Exception& e) {
		return false;
	}
}

Consumer Zlib::DoDecompress(Consumer consumer, ReadMode mode) const noexcept {
	Producer producer;

	std::thread([consumer, producer, mode = mode]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			DataType decompressedBuffer;
			CryptoPP::ZlibDecompressor decompressor(
				new CryptoPP::StringSinkTemplate<DataType>(decompressedBuffer)
			);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				bool read_ok;
				if (mode == ReadMode::Copy)
					read_ok = consumer.Read(bytesToRead, data);
				else
					read_ok = consumer.Extract(bytesToRead, data);
				if (!read_ok) {
					producer.SetError();
					return;
				}

				decompressor.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
				decompressor.Flush(true);
				if (!decompressedBuffer.empty()) {
					producer.Write(std::move(decompressedBuffer));
					decompressedBuffer.clear();
				}
			}
			decompressor.MessageEnd();
			if (!decompressedBuffer.empty()) {
				producer.Write(std::move(decompressedBuffer));
			}
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}