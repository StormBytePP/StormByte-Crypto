#include <StormByte/crypto/compressor.hxx>
#include <StormByte/crypto/implementation/compressor/bzip2.hxx>
#include <StormByte/crypto/implementation/compressor/gzip.hxx>

using namespace StormByte::Crypto;

Compressor::Compressor(const Algorithm::Compress& algorithm) noexcept
:m_algorithm(algorithm) {}

StormByte::Expected<std::string, Exception> Compressor::Compress(const std::string& input) const noexcept {
	Implementation::Compressor::ExpectedCompressorBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			outbuff = Implementation::Compressor::BZip2::Compress(input);
			break;
		case Algorithm::Compress::Gzip:
			outbuff = Implementation::Compressor::Gzip::Compress(input);
			break;
		default:
			return input;
	}

	if (outbuff.has_value()) {
		auto data = outbuff.value().Extract(0);
		if (!data.has_value()) {
			return StormByte::Unexpected<Exception>("Failed to extract data from buffer");
		}
		std::string result(reinterpret_cast<const char*>(data.value().data()), data.value().size());
		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Expected<StormByte::Buffer::FIFO, StormByte::Crypto::Exception> Compressor::Compress(const Buffer::FIFO& buffer) const noexcept {
	Implementation::Compressor::ExpectedCompressorBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			outbuff = Implementation::Compressor::BZip2::Compress(buffer);
			break;
		case Algorithm::Compress::Gzip:
			outbuff = Implementation::Compressor::Gzip::Compress(buffer);
			break;
		default:
			return buffer;
	}

	if (outbuff.has_value()) {
		return outbuff.value();
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffer::Consumer Compressor::Compress(const Buffer::Consumer consumer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			return Implementation::Compressor::BZip2::Compress(consumer);
		case Algorithm::Compress::Gzip:
			return Implementation::Compressor::Gzip::Compress(consumer);
		default:
			return consumer;
	}
}

StormByte::Expected<std::string, Exception> Compressor::Decompress(const std::string& input) const noexcept {
	Implementation::Compressor::ExpectedCompressorBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			outbuff = Implementation::Compressor::BZip2::Decompress(input);
			break;
		case Algorithm::Compress::Gzip:
			outbuff = Implementation::Compressor::Gzip::Decompress(input);
			break;
		default:
			return input;
	}

	if (outbuff.has_value()) {
		auto data = outbuff.value().Extract(0);
		if (!data.has_value()) {
			return StormByte::Unexpected<Exception>("Failed to extract data from buffer");
		}
		std::string result(reinterpret_cast<const char*>(data.value().data()), data.value().size());
		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Expected<StormByte::Buffer::FIFO, StormByte::Crypto::Exception> Compressor::Decompress(const Buffer::FIFO& buffer) const noexcept {
	Implementation::Compressor::ExpectedCompressorBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			outbuff = Implementation::Compressor::BZip2::Decompress(buffer);
			break;
		case Algorithm::Compress::Gzip:
			outbuff = Implementation::Compressor::Gzip::Decompress(buffer);
			break;
		default:
			return buffer;
	}

	if (outbuff.has_value()) {
		return outbuff.value();
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffer::Consumer Compressor::Decompress(const Buffer::Consumer consumer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			return Implementation::Compressor::BZip2::Decompress(consumer);
		case Algorithm::Compress::Gzip:
			return Implementation::Compressor::Gzip::Decompress(consumer);
		default:
			return consumer;
	}
}