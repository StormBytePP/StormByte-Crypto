#pragma once

#include <StormByte/buffers/consumer.hxx>
#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/expected.hxx>

#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	class STORMBYTE_CRYPTO_PUBLIC Compressor final {
		public:
			/**
			 * @brief Initializes a Compressor instance with the specified compression algorithm.
			 * @param algorithm The compression algorithm to use
			 */
			explicit Compressor(const Algorithm::Compress& algorithm) noexcept;

			Compressor(const Compressor& compressor) 					= default;

			Compressor(Compressor&& compressor) noexcept 				= default;

			~Compressor() noexcept 										= default;

			Compressor& operator=(const Compressor& compressor) 		= default;

			Compressor& operator=(Compressor&& compressor) noexcept 	= default;

			Expected<std::string, Exception>							Compress(const std::string& input) const noexcept;

			Expected<Buffers::Simple, Exception>						Compress(const Buffers::Simple& buffer) const noexcept;
			
			Buffers::Consumer 											Compress(const Buffers::Consumer consumer) const noexcept;

			Expected<std::string, Exception>							Decompress(const std::string& input) const noexcept;

			Expected<Buffers::Simple, Exception>						Decompress(const Buffers::Simple& buffer) const noexcept;

			Buffers::Consumer 											Decompress(const Buffers::Consumer consumer) const noexcept;

		private:
			const Algorithm::Compress m_algorithm;
	};
}