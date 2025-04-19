#include <StormByte/crypto/compressor.hxx>
#include <StormByte/crypto/implementation/compressor/bzip2.hxx>
#include <StormByte/crypto/implementation/compressor/gzip.hxx>

using namespace StormByte::Crypto;

Compressor::Compressor(const Algorithm::Compress& algorithm) noexcept
:m_algorithm(algorithm) {}

StormByte::Expected<std::string, Exception> Compressor::Compress(const std::string& input) const noexcept {
	Implementation::Compressor::ExpectedCompressorFutureBuffer outbuff;
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
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the compressed data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Expected<StormByte::Buffers::Simple, StormByte::Crypto::Exception> Compressor::Compress(const Buffers::Simple& buffer) const noexcept {
	Implementation::Compressor::ExpectedCompressorFutureBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			outbuff = Implementation::Compressor::BZip2::Compress(buffer);
			break;
		case Algorithm::Compress::Gzip:
			outbuff = Implementation::Compressor::Gzip::Compress(buffer);
			break;
		default:
			auto span = buffer.Span(); // Get the span of bytes
			return std::string(reinterpret_cast<const char*>(span.data()), span.size());
	}

	if (outbuff.has_value()) {
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the compressed data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffers::Consumer Compressor::Compress(const Buffers::Consumer consumer) const noexcept {
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
	Implementation::Compressor::ExpectedCompressorFutureBuffer outbuff;
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
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the decompressed data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Expected<StormByte::Buffers::Simple, StormByte::Crypto::Exception> Compressor::Decompress(const Buffers::Simple& buffer) const noexcept {
	Implementation::Compressor::ExpectedCompressorFutureBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			outbuff = Implementation::Compressor::BZip2::Decompress(buffer);
			break;
		case Algorithm::Compress::Gzip:
			outbuff = Implementation::Compressor::Gzip::Decompress(buffer);
			break;
		default:
			auto span = buffer.Span(); // Get the span of bytes
			return std::string(reinterpret_cast<const char*>(span.data()), span.size());
	}

	if (outbuff.has_value()) {
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the decompressed data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffers::Consumer Compressor::Decompress(const Buffers::Consumer consumer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Compress::Bzip2:
			return Implementation::Compressor::BZip2::Decompress(consumer);
		case Algorithm::Compress::Gzip:
			return Implementation::Compressor::Gzip::Decompress(consumer);
		default:
			return consumer;
	}
}