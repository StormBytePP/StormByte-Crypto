#pragma once

#include <StormByte/crypto/crypter.hxx>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	class STORMBYTE_CRYPTO_PUBLIC Symmetric final: public Crypter {
		public:
			/** Creates with random password **/
			Symmetric(const Algorithm::Symmetric& algorithm, const size_t& password_size = 16) noexcept;	

			explicit Symmetric(const Algorithm::Symmetric& algorithm, const std::string& password) noexcept;

			Symmetric(const Symmetric& crypter) 					= default;

			Symmetric(Symmetric&& crypter) noexcept 				= default;

			~Symmetric() noexcept override 							= default;

			Symmetric& operator=(const Symmetric& crypter) 			= default;

			Symmetric& operator=(Symmetric&& crypter) noexcept 		= default;

			[[nodiscard]]
			Expected<std::string, Exception> 						Encrypt(const std::string& input) const noexcept override;

			[[nodiscard]]
			Expected<Buffers::Simple, Exception> 					Encrypt(const Buffers::Simple& buffer) const noexcept override;

			[[nodiscard]]
			Buffers::Consumer 										Encrypt(const Buffers::Consumer consumer) const noexcept override;

			Expected<std::string, Exception> 						Decrypt(const std::string& input) const noexcept override;

			Expected<Buffers::Simple, Exception> 					Decrypt(const Buffers::Simple& buffer) const noexcept override;

			Buffers::Consumer 										Decrypt(const Buffers::Consumer consumer) const noexcept override;

			const std::string& 										Password() const noexcept;

			void 													Password(const std::string& password) noexcept;

			void 													Password(std::string&& password) noexcept;

		private:
			Algorithm::Symmetric m_algorithm;						///< The symmetric encryption algorithm to use
			std::string m_password;									///< The password used for encryption/decryption
	};
}