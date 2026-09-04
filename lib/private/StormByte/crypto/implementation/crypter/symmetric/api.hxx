/*
* Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
*
* This file is part of StormByte-Crypto.
*
* StormByte-Crypto is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License version 3
* or later, as published by the Free Software Foundation.
*
* StormByte-Crypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with StormByte-Crypto. If not, see
* <https://www.gnu.org/licenses/lgpl-3.0.html>.
*/

#pragma once

#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/implementation/crypter/details.hxx>
#include <StormByte/crypto/implementation/crypter/symmetric/details.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <cstring>
#include <filters.h>
#include <gcm.h>
#include <memory>
#include <modes.h>
#include <secblock.h>
#include <span>
#include <vector>

/**
 * @brief Private symmetric crypter implementation.
 */
namespace StormByte::Crypto::Implementation::Crypter::Symmetric {
	/**
	 * @brief One-shot CBC encrypt.
	 * @tparam AlgoT Algorithm traits (DEFAULT_KEYLENGTH).
	 * @tparam CryptorT Crypto++ CBC encryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param dataSpan Input.
	 * @param password Password.
	 * @param output Destination.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @return true on success.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	bool EncryptCBC(std::span<const std::byte> dataSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		/**
		 * @struct Ops
		 * @brief One-shot CBC encrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			std::unique_ptr<CryptorT> encryption;	///< Cipher

			/**
			 * @brief Construct sized blocks.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Emit salt||IV and arm the cipher.
			 * @param outChunk Header bytes.
			 * @return true on success.
			 */
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

			/**
			 * @brief Encrypt one chunk.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Nothing left after the last Process.
			 * @return true.
			 */
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
	 * @brief Streaming CBC encrypt.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam CryptorT Crypto++ CBC encryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param consumer Input consumer.
	 * @param password Password.
	 * @param mode Copy or move.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @return Consumer with salt||IV||ciphertext.
	 */
	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	Buffer::Consumer EncryptCBC(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		/**
		 * @struct Ops
		 * @brief Streaming CBC encrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			std::unique_ptr<CryptorT> encryption;	///< Cipher
			Buffer::DataType buffer;				///< Filter sink
			std::unique_ptr<CryptoPP::StreamTransformationFilter> filter;	///< Live filter

			/**
			 * @brief Construct sized blocks.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Emit salt||IV, arm cipher and filter.
			 * @param outChunk Header bytes.
			 * @return true on success.
			 */
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

			/**
			 * @brief Encrypt one chunk through the live filter.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Finish the filter (padding).
			 * @param outChunk Remaining output.
			 * @return true on success.
			 */
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

	/**
	 * @brief One-shot CBC decrypt.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam DecryptorT Crypto++ CBC decryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param dataSpan Input (salt||IV||ciphertext).
	 * @param password Password.
	 * @param output Destination.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @return true on success.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	bool DecryptCBC(std::span<const std::byte> dataSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		/**
		 * @struct Ops
		 * @brief One-shot CBC decrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			std::unique_ptr<DecryptorT> decryption;	///< Cipher

			/**
			 * @brief Construct sized blocks.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Consume salt||IV from the span and arm the cipher.
			 * @param in Remaining input after the header.
			 * @return true on success.
			 */
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

			/**
			 * @brief Decrypt one chunk.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Nothing left after the last Process.
			 * @return true.
			 */
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
	 * @brief Streaming CBC decrypt.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam DecryptorT Crypto++ CBC decryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param consumer Input consumer.
	 * @param password Password.
	 * @param mode Copy or move.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @return Consumer with the plaintext.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	Buffer::Consumer DecryptCBC(Buffer::Consumer consumer,
								Password password,
								ReadMode mode,
								const std::size_t& salt_size,
								const std::size_t& iv_size,
								const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		/**
		 * @struct Ops
		 * @brief Streaming CBC decrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			std::unique_ptr<DecryptorT> decryption;	///< Cipher
			Buffer::DataType buffer;				///< Filter sink
			std::unique_ptr<CryptoPP::StreamTransformationFilter> filter;	///< Live filter

			/**
			 * @brief Construct sized blocks.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Extract salt||IV from the consumer and arm the filter.
			 * @param consumer Input consumer.
			 * @return true on success.
			 */
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

			/**
			 * @brief Decrypt one chunk through the live filter.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Finish the filter (padding).
			 * @param outChunk Remaining output.
			 * @return true on success.
			 */
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

	/**
	 * @brief One-shot GCM encrypt.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam CryptorT Crypto++ GCM encryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param dataSpan Input.
	 * @param password Password.
	 * @param output Destination.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @param aad Additional authenticated data.
	 * @return true on success.
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
		/**
		 * @struct Ops
		 * @brief One-shot GCM encrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			std::vector<std::byte> aad;				///< AAD copy
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			CryptorT encryption;					///< Cipher
			bool ready = false;						///< Header written

			/**
			 * @brief Construct sized blocks and copy AAD.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 * @param a AAD.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Emit salt||IV and arm the cipher.
			 * @param outChunk Header bytes.
			 * @return true on success.
			 */
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

			/**
			 * @brief Encrypt the whole remaining input (tag in MessageEnd).
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Tag already emitted in Process.
			 * @return true.
			 */
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
	 * @brief Streaming GCM encrypt.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam CryptorT Crypto++ GCM encryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param consumer Input consumer.
	 * @param password Password.
	 * @param mode Copy or move.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @param aad Additional authenticated data.
	 * @return Consumer with salt||IV||ciphertext||tag.
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
		/**
		 * @struct Ops
		 * @brief Streaming GCM encrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			std::vector<std::byte> aad;				///< AAD copy
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			CryptorT encryption;					///< Cipher
			Buffer::DataType buffer;				///< Filter sink
			std::unique_ptr<CryptoPP::AuthenticatedEncryptionFilter> filter;	///< Live filter

			/**
			 * @brief Construct sized blocks and copy AAD.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 * @param a AAD.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Emit salt||IV, arm filter, push AAD.
			 * @param outChunk Header bytes.
			 * @return true on success.
			 */
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

			/**
			 * @brief Encrypt one chunk.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Finish and emit the tag.
			 * @param outChunk Remaining output.
			 * @return true on success.
			 */
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

	/**
	 * @brief One-shot GCM decrypt (no AAD).
	 * @tparam AlgoT Algorithm traits.
	 * @tparam DecryptorT Crypto++ GCM decryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param encryptedSpan Input.
	 * @param password Password.
	 * @param output Destination.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @return true on success.
	 */
	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	bool DecryptGCM(std::span<const std::byte> encryptedSpan,
					const Password& password,
					Buffer::WriteOnly& output,
					const std::size_t& salt_size,
					const std::size_t& iv_size,
					const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept
	{
		/**
		 * @struct Ops
		 * @brief One-shot GCM decrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			DecryptorT decryption;					///< Cipher
			bool ready = false;						///< Header consumed

			/**
			 * @brief Construct sized blocks.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Consume salt||IV from the span.
			 * @param in Remaining input after the header.
			 * @return true on success.
			 */
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

			/**
			 * @brief Decrypt and verify the tag.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Tag already verified in Process.
			 * @return true.
			 */
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
	 * @brief Streaming GCM decrypt.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam DecryptorT Crypto++ GCM decryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param consumer Input consumer.
	 * @param password Password.
	 * @param mode Copy or move.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @param aad Additional authenticated data.
	 * @return Consumer with the plaintext.
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
		/**
		 * @struct Ops
		 * @brief Streaming GCM decrypt engine.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			std::vector<std::byte> aad;				///< AAD copy
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			DecryptorT decryption;					///< Cipher
			Buffer::DataType buffer;				///< Filter sink
			std::unique_ptr<CryptoPP::AuthenticatedDecryptionFilter> filter;	///< Live filter

			/**
			 * @brief Construct sized blocks and copy AAD.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 * @param a AAD.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Extract salt||IV, arm filter, push AAD.
			 * @param consumer Input consumer.
			 * @return true on success.
			 */
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

			/**
			 * @brief Decrypt one chunk.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Finish and verify the tag.
			 * @param outChunk Remaining output.
			 * @return true if the tag matches.
			 */
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

	/**
	 * @brief One-shot AEAD encrypt. Delegates to EncryptGCM.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam CryptorT Crypto++ AEAD encryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param dataSpan Input.
	 * @param password Password.
	 * @param output Destination.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @param aad Additional authenticated data.
	 * @return true on success.
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
	 * @brief Streaming AEAD encrypt. Delegates to EncryptGCM.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam CryptorT Crypto++ AEAD encryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param consumer Input consumer.
	 * @param password Password.
	 * @param mode Copy or move.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @param aad Additional authenticated data.
	 * @return Consumer with the envelope.
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
	 * @brief One-shot AEAD decrypt with AAD.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam DecryptorT Crypto++ AEAD decryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param encryptedSpan Input.
	 * @param password Password.
	 * @param output Destination.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @param aad Additional authenticated data.
	 * @return true on success.
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
		/**
		 * @struct Ops
		 * @brief One-shot AEAD decrypt engine with AAD.
		 */
		struct Ops final : Crypter::Ops {
			Password password;						///< Password material
			std::size_t salt_size, iv_size, key_size;	///< Sizes
			std::vector<std::byte> aad;				///< AAD copy
			CryptoPP::SecByteBlock salt, iv, key;	///< Salt, IV, derived key
			DecryptorT decryption;					///< Cipher
			bool ready = false;						///< Header consumed

			/**
			 * @brief Construct sized blocks and copy AAD.
			 * @param p Password.
			 * @param ss Salt size.
			 * @param is IV size.
			 * @param ks Key size.
			 * @param a AAD.
			 */
			Ops(Password p, std::size_t ss, std::size_t is, std::size_t ks,
				std::span<const std::byte> a)
				: password(std::move(p)), salt_size(ss), iv_size(is), key_size(ks)
				, aad(a.begin(), a.end())
				, salt(ss), iv(is), key(ks) {}

			/**
			 * @brief Wipe key material.
			 */
			~Ops() override {
				Helpers::SecureWipe(key);
				Helpers::SecureWipe(salt);
				Helpers::SecureWipe(iv);
			}

			/**
			 * @brief Consume salt||IV from the span.
			 * @param in Remaining input after the header.
			 * @return true on success.
			 */
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

			/**
			 * @brief Decrypt and verify with AAD.
			 * @param in Input.
			 * @param outChunk Output.
			 * @return true on success.
			 */
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

			/**
			 * @brief Tag already verified in Process.
			 * @return true.
			 */
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
	 * @brief Streaming AEAD decrypt. Delegates to DecryptGCM.
	 * @tparam AlgoT Algorithm traits.
	 * @tparam DecryptorT Crypto++ AEAD decryption type.
	 * @tparam CryptoHMAC Hash for PBKDF2.
	 * @param consumer Input consumer.
	 * @param password Password.
	 * @param mode Copy or move.
	 * @param salt_size Salt length.
	 * @param iv_size IV length.
	 * @param key_size Key length.
	 * @param aad Additional authenticated data.
	 * @return Consumer with the plaintext.
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
