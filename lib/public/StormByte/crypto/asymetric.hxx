#pragma once

#include <StormByte/crypto/crypter.hxx>
#include <StormByte/crypto/keypair.hxx>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	class STORMBYTE_CRYPTO_PUBLIC Asymmetric final: public Crypter {
		public:
			explicit Asymmetric(const Algorithm::Asymmetric& algorithm, const KeyPair& key_pair) noexcept;

			explicit Asymmetric(const Algorithm::Asymmetric& algorithm, KeyPair&& key_pair) noexcept;	

			Asymmetric(const Asymmetric& crypter) 					= default;

			Asymmetric(Asymmetric&& crypter) noexcept 				= default;

			~Asymmetric() noexcept override 						= default;

			Asymmetric& operator=(const Asymmetric& crypter) 		= default;

			Asymmetric& operator=(Asymmetric&& crypter) noexcept 	= default;

			Expected<std::string, Exception> 						Encrypt(const std::string& input) const noexcept override;

			Expected<Buffers::Simple, Exception> 					Encrypt(const Buffers::Simple& buffer) const noexcept override;

			Buffers::Consumer 										Encrypt(const Buffers::Consumer consumer) const noexcept override;

			Expected<std::string, Exception> 						Decrypt(const std::string& input) const noexcept override;

			Expected<Buffers::Simple, Exception> 					Decrypt(const Buffers::Simple& buffer) const noexcept override;

			Buffers::Consumer 										Decrypt(const Buffers::Consumer consumer) const noexcept override;

			const KeyPair& 											KeyPair() const noexcept;

		private:
			Algorithm::Asymmetric m_algorithm;						///< The Asymmetric encryption algorithm to use
			class KeyPair m_keys;									///< The key pair used for encryption/decryption
	};
}