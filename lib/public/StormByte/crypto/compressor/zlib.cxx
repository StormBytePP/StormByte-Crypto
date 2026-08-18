#include <StormByte/crypto/compressor/zlib.hxx>
#include <StormByte/crypto/implementation/compressor/details.hxx>
#include <StormByte/buffer/producer.hxx>

#include <algorithm>
#include <filters.h>
#include <memory>
#include <zlib.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using namespace StormByte::Crypto::Compressor;

namespace {
	struct ZlibCompressOps final : StormByte::Crypto::Implementation::Compressor::StreamOps {
		DataType buffer;
		std::unique_ptr<CryptoPP::ZlibCompressor> compressor;

		explicit ZlibCompressOps(unsigned short level)
		{
			compressor = std::make_unique<CryptoPP::ZlibCompressor>(
				new CryptoPP::StringSinkTemplate<DataType>(buffer),
				level
			);
		}

		bool Process(std::span<const std::byte> in, DataType& out) override
		{
			try {
				compressor->Put(
					reinterpret_cast<const uint8_t*>(in.data()),
					in.size_bytes());
				compressor->Flush(true);
				out = std::move(buffer);
				buffer.clear();
				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(DataType& out) override
		{
			try {
				compressor->MessageEnd();
				out = std::move(buffer);
				buffer.clear();
				compressor.reset();
				return true;
			} catch (...) {
				return false;
			}
		}
	};

	struct ZlibDecompressOps final : StormByte::Crypto::Implementation::Compressor::StreamOps {
		DataType buffer;
		std::unique_ptr<CryptoPP::ZlibDecompressor> decompressor;

		ZlibDecompressOps()
		{
			decompressor = std::make_unique<CryptoPP::ZlibDecompressor>(
				new CryptoPP::StringSinkTemplate<DataType>(buffer)
			);
		}

		bool Process(std::span<const std::byte> in, DataType& out) override
		{
			try {
				decompressor->Put(
					reinterpret_cast<const uint8_t*>(in.data()),
					in.size_bytes());
				decompressor->Flush(true);
				out = std::move(buffer);
				buffer.clear();
				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(DataType& out) override
		{
			try {
				decompressor->MessageEnd();
				out = std::move(buffer);
				buffer.clear();
				decompressor.reset();
				return true;
			} catch (...) {
				return false;
			}
		}
	};
}

Zlib::Zlib(unsigned short level)
	: Generic(Type::Zlib,
			std::clamp<unsigned short>(
				static_cast<unsigned short>(level),
				1,
				CryptoPP::ZlibCompressor::MAX_DEFLATE_LEVEL))
{}

bool Zlib::DoCompress(std::span<const std::byte> input, WriteOnly& output) const noexcept
{
	return Implementation::Compressor::ProcessSpan(
		input, output, std::make_unique<ZlibCompressOps>(m_level));
}

Consumer Zlib::DoCompress(Consumer consumer, ReadMode mode) const noexcept
{
	return Implementation::Compressor::Stream(
		std::move(consumer), mode, std::make_unique<ZlibCompressOps>(m_level));
}

bool Zlib::DoDecompress(std::span<const std::byte> input, WriteOnly& output) const noexcept
{
	return Implementation::Compressor::ProcessSpan(
		input, output, std::make_unique<ZlibDecompressOps>());
}

Consumer Zlib::DoDecompress(Consumer consumer, ReadMode mode) const noexcept
{
	return Implementation::Compressor::Stream(
		std::move(consumer), mode, std::make_unique<ZlibDecompressOps>());
}
