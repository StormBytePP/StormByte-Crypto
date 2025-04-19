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
	class STORMBYTE_CRYPTO_PUBLIC Crypter {
		public:
			Crypter() noexcept									= default;

			Crypter(const Crypter& crypter) 					= default;

			Crypter(Crypter&& crypter) noexcept 				= default;

			virtual ~Crypter() noexcept 						= default;

			Crypter& operator=(const Crypter& crypter) 			= default;

			Crypter& operator=(Crypter&& crypter) noexcept 		= default;

			[[nodiscard]]
			virtual Expected<std::string, Exception>			Encrypt(const std::string& input) const noexcept = 0;

			[[nodiscard]]
			virtual Expected<Buffers::Simple, Exception>		Encrypt(const Buffers::Simple& buffer) const noexcept = 0;

			[[nodiscard]]
			virtual Buffers::Consumer 							Encrypt(const Buffers::Consumer consumer) const noexcept = 0;

			[[nodiscard]]
			virtual Expected<std::string, Exception>			Decrypt(const std::string& input) const noexcept = 0;

			[[nodiscard]]
			virtual Expected<Buffers::Simple, Exception>		Decrypt(const Buffers::Simple& buffer) const noexcept = 0;

			[[nodiscard]]
			virtual Buffers::Consumer 							Decrypt(const Buffers::Consumer consumer) const noexcept = 0;
	};
}