#pragma once

#include <StormByte/crypto/implementation/crypter/details.hxx>
#include <StormByte/crypto/implementation/crypter/symmetric/details.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filters.h>
#include <gcm.h>
#include <modes.h>
#include <secblock.h>
#include <span>
#include <memory>
#include <cstring>
#include <vector>

namespace StormByte::Crypto::Implementation::Crypter::Symmetric {
	// =========================================================================
	// CBC ENCRYPT
	// =========================================================================

	/**
	 * @brief One-shot CBC encryption.
	 * @tparam AlgoT      Algorithm traits (provides DEFAULT_KEYLENGTH).
	 * @tparam CryptorT   Encryption object (e.g. CBC_Mode<AES>::Encryption).
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	bool EncryptCBC(std::span<const std::byte> dataSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			CryptoPP::SecByteBlock salt, iv, key;
			std::unique_ptr<CryptorT> encryption;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool WriteHeader(Buffer::DataType& outChunk) override
			{
				try {
					RNG().GenerateBlock(salt, salt.size());
					RNG().GenerateBlock(iv, iv.size());
					DeriveKey<CryptoHMAC>(key, salt, password);
					encryption = std::make_unique<CryptorT>(key, key.size(), iv);

					outChunk.reserve(salt.size() + iv.size());
					for (size_t i = 0; i < salt.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(salt[i]));
					for (size_t i = 0; i < iv.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(iv[i]));

					Helpers::SecureWipe(salt);
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				if (!encryption)
					return false;
				try {
					CryptoPP::StringSource ss(
						reinterpret_cast<const uint8_t*>(in.data()),
						in.size_bytes(),
						true,
						new CryptoPP::StreamTransformationFilter(
							*encryption,
							new CryptoPP::StringSinkTemplate<Buffer::DataType>(outChunk)
						)
					);
					(void)ss;
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& /*outChunk*/) override
			{
				return true;
			}
		};

		return Crypter::ProcessSpan(
			dataSpan, output,
			std::make_unique<Ops>(password, salt_size, iv_size, key_size));
	}

	/**
	 * @brief Streaming CBC encryption.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	Buffer::Consumer EncryptCBC(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			CryptoPP::SecByteBlock salt, iv, key;
			std::unique_ptr<CryptorT> encryption;
			Buffer::DataType buffer;
			std::unique_ptr<CryptoPP::StreamTransformationFilter> filter;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool WriteHeader(Buffer::DataType& outChunk) override
			{
				try {
					RNG().GenerateBlock(salt, salt.size());
					RNG().GenerateBlock(iv, iv.size());
					DeriveKey<CryptoHMAC>(key, salt, password);
					encryption = std::make_unique<CryptorT>(key, key.size(), iv);

					outChunk.reserve(salt.size() + iv.size());
					for (size_t i = 0; i < salt.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(salt[i]));
					for (size_t i = 0; i < iv.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(iv[i]));

					Helpers::SecureWipe(salt);

					filter = std::make_unique<CryptoPP::StreamTransformationFilter>(
						*encryption,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(buffer)
					);
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				try {
					filter->Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
					outChunk = std::move(buffer);
					buffer.clear();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& outChunk) override
			{
				try {
					filter->MessageEnd();
					outChunk = std::move(buffer);
					buffer.clear();
					filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		return Crypter::Stream(
			std::move(consumer), mode,
			std::make_unique<Ops>(std::move(password), salt_size, iv_size, key_size));
	}

	// =========================================================================
	// CBC DECRYPT
	// =========================================================================

	/**
	 * @brief One-shot CBC decryption.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	bool DecryptCBC(std::span<const std::byte> dataSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			CryptoPP::SecByteBlock salt, iv, key;
			std::unique_ptr<DecryptorT> decryption;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool ReadHeader(std::span<const std::byte>& in) override
			{
				if (in.size_bytes() < salt_size + iv_size)
					return false;
				try {
					std::memcpy(salt.data(), in.data(), salt_size);
					std::memcpy(iv.data(), in.data() + salt_size, iv_size);
					in = in.subspan(salt_size + iv_size);

					DeriveKey<CryptoHMAC>(key, salt, password);
					decryption = std::make_unique<DecryptorT>(key, key.size(), iv);
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				if (!decryption)
					return false;
				try {
					CryptoPP::StringSource ss(
						reinterpret_cast<const uint8_t*>(in.data()),
						in.size_bytes(),
						true,
						new CryptoPP::StreamTransformationFilter(
							*decryption,
							new CryptoPP::StringSinkTemplate<Buffer::DataType>(outChunk)
						)
					);
					(void)ss;
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& /*outChunk*/) override
			{
				return true;
			}
		};

		return Crypter::ProcessSpan(
			dataSpan, output,
			std::make_unique<Ops>(password, salt_size, iv_size, key_size));
	}

	/**
	 * @brief Streaming CBC decryption.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	Buffer::Consumer DecryptCBC(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			CryptoPP::SecByteBlock salt, iv, key;
			std::unique_ptr<DecryptorT> decryption;
			Buffer::DataType buffer;
			std::unique_ptr<CryptoPP::StreamTransformationFilter> filter;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool ReadHeader(Buffer::Consumer& consumer) override
			{
				try {
					Buffer::DataType saltData;
					if (!consumer.Extract(salt.size(), saltData))
						return false;
					std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()),
								salt.size(), salt.data());

					Buffer::DataType ivData;
					if (!consumer.Extract(iv.size(), ivData))
						return false;
					std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()),
								iv.size(), iv.data());

					DeriveKey<CryptoHMAC>(key, salt, password);
					decryption = std::make_unique<DecryptorT>(key, key.size(), iv);

					filter = std::make_unique<CryptoPP::StreamTransformationFilter>(
						*decryption,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(buffer)
					);
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				try {
					filter->Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
					outChunk = std::move(buffer);
					buffer.clear();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& outChunk) override
			{
				try {
					filter->MessageEnd();
					outChunk = std::move(buffer);
					buffer.clear();
					filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		return Crypter::Stream(
			std::move(consumer), mode,
			std::make_unique<Ops>(std::move(password), salt_size, iv_size, key_size));
	}

	// =========================================================================
	// GCM ENCRYPT
	// =========================================================================

	/**
	 * @brief One-shot GCM encryption.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	bool EncryptGCM(std::span<const std::byte> dataSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH,
					std::span<const std::byte> aad = {}) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			std::vector<std::byte> aad;
			CryptoPP::SecByteBlock salt, iv, key;
			CryptorT encryption;
			bool ready = false;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool WriteHeader(Buffer::DataType& outChunk) override
			{
				try {
					RNG().GenerateBlock(salt, salt.size());
					RNG().GenerateBlock(iv, iv.size());
					DeriveKey<CryptoHMAC>(key, salt, password);
					SetKeyIV(encryption, key, key.size(), iv, iv.size());

					outChunk.reserve(salt.size() + iv.size());
					for (size_t i = 0; i < salt.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(salt[i]));
					for (size_t i = 0; i < iv.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(iv[i]));

					Helpers::SecureWipe(salt);
					ready = true;
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				if (!ready)
					return false;
				try {
					CryptoPP::AuthenticatedEncryptionFilter ef(
						encryption,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(outChunk)
					);
					if (!aad.empty()) {
						ef.ChannelPut2("AAD",
							reinterpret_cast<const CryptoPP::byte*>(aad.data()),
							aad.size(), 0, false);
					}
					ef.Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
					ef.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& /*outChunk*/) override
			{
				return true;
			}
		};

		return Crypter::ProcessSpan(
			dataSpan, output,
			std::make_unique<Ops>(password, salt_size, iv_size, key_size, aad));
	}

	/**
	 * @brief Streaming GCM encryption.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	Buffer::Consumer EncryptGCM(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH,
								std::span<const std::byte> aad = {}) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			std::vector<std::byte> aad;
			CryptoPP::SecByteBlock salt, iv, key;
			CryptorT encryption;
			Buffer::DataType buffer;
			std::unique_ptr<CryptoPP::AuthenticatedEncryptionFilter> filter;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool WriteHeader(Buffer::DataType& outChunk) override
			{
				try {
					RNG().GenerateBlock(salt, salt.size());
					RNG().GenerateBlock(iv, iv.size());
					DeriveKey<CryptoHMAC>(key, salt, password);
					SetKeyIV(encryption, key, key.size(), iv, iv.size());

					outChunk.reserve(salt.size() + iv.size());
					for (size_t i = 0; i < salt.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(salt[i]));
					for (size_t i = 0; i < iv.size(); ++i)
						outChunk.push_back(static_cast<std::byte>(iv[i]));

					Helpers::SecureWipe(salt);

					filter = std::make_unique<CryptoPP::AuthenticatedEncryptionFilter>(
						encryption,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(buffer)
					);
					if (!aad.empty()) {
						filter->ChannelPut2("AAD",
							reinterpret_cast<const CryptoPP::byte*>(aad.data()),
							aad.size(), 0, false);
					}
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				try {
					filter->Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
					outChunk = std::move(buffer);
					buffer.clear();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& outChunk) override
			{
				try {
					filter->MessageEnd();
					outChunk = std::move(buffer);
					buffer.clear();
					filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		return Crypter::Stream(
			std::move(consumer), mode,
			std::make_unique<Ops>(std::move(password), salt_size, iv_size, key_size, aad));
	}

	// =========================================================================
	// GCM DECRYPT
	// =========================================================================

	/**
	 * @brief One-shot GCM decryption.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	bool DecryptGCM(std::span<const std::byte> encryptedSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			CryptoPP::SecByteBlock salt, iv, key;
			DecryptorT decryption;
			bool ready = false;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool ReadHeader(std::span<const std::byte>& in) override
			{
				if (in.size_bytes() < salt_size + iv_size)
					return false;
				try {
					std::memcpy(salt.data(), in.data(), salt_size);
					std::memcpy(iv.data(), in.data() + salt_size, iv_size);
					in = in.subspan(salt_size + iv_size);

					DeriveKey<CryptoHMAC>(key, salt, password);
					SetKeyIV(decryption, key, key.size(), iv, iv.size());
					ready = true;
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				if (!ready)
					return false;
				try {
					CryptoPP::AuthenticatedDecryptionFilter df(
						decryption,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(outChunk),
						CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
					);
					df.Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
					df.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& /*outChunk*/) override
			{
				return true;
			}
		};

		return Crypter::ProcessSpan(
			encryptedSpan, output,
			std::make_unique<Ops>(password, salt_size, iv_size, key_size));
	}

	/**
	 * @brief Streaming GCM decryption.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	Buffer::Consumer DecryptGCM(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH,
								std::span<const std::byte> aad = {}) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			std::vector<std::byte> aad;
			CryptoPP::SecByteBlock salt, iv, key;
			DecryptorT decryption;
			Buffer::DataType buffer;
			std::unique_ptr<CryptoPP::AuthenticatedDecryptionFilter> filter;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool ReadHeader(Buffer::Consumer& consumer) override
			{
				try {
					Buffer::DataType saltData;
					if (!consumer.Extract(salt.size(), saltData))
						return false;
					std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()),
								salt.size(), salt.data());

					Buffer::DataType ivData;
					if (!consumer.Extract(iv.size(), ivData))
						return false;
					std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()),
								iv.size(), iv.data());

					DeriveKey<CryptoHMAC>(key, salt, password);
					SetKeyIV(decryption, key, key.size(), iv, iv.size());

					filter = std::make_unique<CryptoPP::AuthenticatedDecryptionFilter>(
						decryption,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(buffer),
						CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
					);
					if (!aad.empty()) {
						filter->ChannelPut2("AAD",
							reinterpret_cast<const CryptoPP::byte*>(aad.data()),
							aad.size(), 0, false);
					}
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				try {
					filter->Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
					outChunk = std::move(buffer);
					buffer.clear();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& outChunk) override
			{
				try {
					filter->MessageEnd();
					outChunk = std::move(buffer);
					buffer.clear();
					filter.reset();
					return true;
				} catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed&) {
					return false;
				} catch (...) {
					return false;
				}
			}
		};

		return Crypter::Stream(
			std::move(consumer), mode,
			std::make_unique<Ops>(std::move(password), salt_size, iv_size, key_size, aad));
	}

	// =========================================================================
	// AEAD
	// =========================================================================

	/**
	 * @brief One-shot AEAD encryption.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	bool EncryptAEAD(std::span<const std::byte> dataSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH,
					std::span<const std::byte> aad = {}) noexcept
	{
		return EncryptGCM<AlgoT, CryptorT, CryptoHMAC>(
			dataSpan, password, output, salt_size, iv_size, key_size, aad);
	}

	/**
	 * @brief Streaming AEAD encryption.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	Buffer::Consumer EncryptAEAD(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH,
								std::span<const std::byte> aad = {}) noexcept
	{
		return EncryptGCM<AlgoT, CryptorT, CryptoHMAC>(
			std::move(consumer), std::move(password), mode,
			salt_size, iv_size, key_size, aad);
	}

	/**
	 * @brief One-shot AEAD decryption (supports AAD).
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	bool DecryptAEAD(std::span<const std::byte> encryptedSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH,
					std::span<const std::byte> aad = {}) noexcept
	{
		struct Ops final : Crypter::Ops {
			Password password;
			std::size_t salt_size, iv_size, key_size;
			std::vector<std::byte> aad;
			CryptoPP::SecByteBlock salt, iv, key;
			DecryptorT decryption;
			bool ready = false;

			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			bool ReadHeader(std::span<const std::byte>& in) override
			{
				if (in.size_bytes() < salt_size + iv_size)
					return false;
				try {
					std::memcpy(salt.data(), in.data(), salt_size);
					std::memcpy(iv.data(), in.data() + salt_size, iv_size);
					in = in.subspan(salt_size + iv_size);

					DeriveKey<CryptoHMAC>(key, salt, password);
					SetKeyIV(decryption, key, key.size(), iv, iv.size());
					ready = true;
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, Buffer::DataType& outChunk) override
			{
				if (!ready)
					return false;
				try {
					CryptoPP::AuthenticatedDecryptionFilter df(
						decryption,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(outChunk),
						CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
					);
					if (!aad.empty()) {
						df.ChannelPut2("AAD",
							reinterpret_cast<const CryptoPP::byte*>(aad.data()),
							aad.size(), 0, false);
					}
					df.Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
					df.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& /*outChunk*/) override
			{
				return true;
			}
		};

		return Crypter::ProcessSpan(
			encryptedSpan, output,
			std::make_unique<Ops>(password, salt_size, iv_size, key_size, aad));
	}

	/**
	 * @brief Streaming AEAD decryption.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	Buffer::Consumer DecryptAEAD(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH,
								std::span<const std::byte> aad = {}) noexcept
	{
		return DecryptGCM<AlgoT, DecryptorT, CryptoHMAC>(
			std::move(consumer), std::move(password), mode,
			salt_size, iv_size, key_size, aad);
	}
}
