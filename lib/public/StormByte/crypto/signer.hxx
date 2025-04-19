#pragma once

#include <StormByte/buffers/consumer.hxx>
#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/keypair.hxx>
#include <StormByte/expected.hxx>

#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	class STORMBYTE_CRYPTO_PUBLIC Signer final {
		public:
			explicit Signer(const Algorithm::Sign& algorithm, const KeyPair& keypair) noexcept;

			explicit Signer(const Algorithm::Sign& algorithm, KeyPair&& keypair) noexcept;

			Signer(const Signer& signer) 					= default;

			Signer(Signer&& signer) noexcept 				= default;

			~Signer() noexcept 								= default;

			Signer& operator=(const Signer& signer) 		= default;

			Signer& operator=(Signer&& signer) noexcept 	= default;

			Expected<std::string, Exception>				Sign(const std::string& input) const noexcept;

			Expected<std::string, Exception>				Sign(const Buffers::Simple& buffer) const noexcept;

			Buffers::Consumer 								Sign(const Buffers::Consumer consumer) const noexcept;

			bool 											Verify(const std::string& message, const std::string& signature) const noexcept;

			bool 											Verify(const Buffers::Simple&, const std::string& signature) const noexcept;

			bool 											Verify(const Buffers::Consumer consumer, const std::string& signature) const noexcept;

		private:
			Algorithm::Sign m_algorithm;					///< The Sign algorithm to use
			class KeyPair m_keys;							///< The key pair used for signing/verifying
	};
};