#include <StormByte/crypto/implementation/encryption/aes_gcm.hxx>
#include <StormByte/crypto/random.hxx>

#include <algorithm>
#include <aes.h>
#include <cryptlib.h>
#include <gcm.h>
#include <hex.h>
#include <filters.h>
#include <format>
#include <secblock.h>
#include <thread>
#include <pwdbased.h>
#include <span>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	ExpectedCryptoBuffer EncryptHelper(std::span<const std::byte> dataSpan, const std::string& password) noexcept {
		try {
			// GCM uses a 12-byte IV (96 bits) for optimal performance
			constexpr size_t saltSize = 16;
			constexpr size_t ivSize = 12;

			CryptoPP::SecByteBlock salt(saltSize);
			CryptoPP::SecByteBlock iv(ivSize);
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

			// Derive key from password
			CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
			password.size(), salt, salt.size(), 10000);

			// Encrypt using GCM mode
			std::vector<uint8_t> encryptedData;
			CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
			encryption.SetKeyWithIV(key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedEncryptionFilter ef(encryption,
				new CryptoPP::VectorSink(encryptedData)
			);

			ef.Put(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes());
			ef.MessageEnd();

			// Prepend salt and IV
			encryptedData.insert(encryptedData.begin(), salt.begin(), salt.end());
			encryptedData.insert(encryptedData.begin() + salt.size(), iv.begin(), iv.end());

			FIFO buffer;
			(void)buffer.Write(std::move(encryptedData));
			return buffer;
		} catch (const std::exception& e) {
			return Unexpected(CrypterException(e.what()));
		}
	}

	ExpectedCryptoBuffer DecryptHelper(std::span<const std::byte> encryptedSpan, const std::string& password) noexcept {
		try {
			constexpr size_t saltSize = 16;
			constexpr size_t ivSize = 12;

			if (encryptedSpan.size_bytes() < saltSize + ivSize) {
				return Unexpected(CrypterException("Encrypted data too short to contain salt and IV"));
			}

			CryptoPP::SecByteBlock salt(saltSize), iv(ivSize);
			std::memcpy(salt.data(), encryptedSpan.data(), saltSize);
			std::memcpy(iv.data(), encryptedSpan.data() + saltSize, ivSize);

			encryptedSpan = encryptedSpan.subspan(saltSize + ivSize);

			// Derive key from password
			CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
			password.size(), salt, salt.size(), 10000);

			// Decrypt using GCM mode
			std::vector<uint8_t> decryptedData;
			CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
			decryption.SetKeyWithIV(key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedDecryptionFilter df(
				decryption,
				new CryptoPP::VectorSink(decryptedData),
				CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
			);

			df.Put(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes());
			df.MessageEnd();

			FIFO buffer;
			(void)buffer.Write(std::move(decryptedData));
			return buffer;
		} catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
			return Unexpected(CrypterException("Authentication failed: {}", e.what()));
		} catch (const std::exception& e) {
			return Unexpected(CrypterException(e.what()));
		}
	}
}

ExpectedCryptoBuffer AES_GCM::Encrypt(const std::string& data, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(data.data()), data.size());
	return EncryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer AES_GCM::Encrypt(const FIFO& data, const std::string& password) noexcept {
	DataType d;
	auto read_ok = data.Read(d);
	if (!read_ok.has_value()) {
		return Unexpected(CrypterException("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(d.data(), d.size());
	return EncryptHelper(dataSpan, password);
}

Consumer AES_GCM::Encrypt(Consumer consumer, const std::string& password) noexcept {
	/** AES-GCM does not support stream so we extract all data at once and call block helpers */
	DataType data;
	Producer producer;
	consumer.ExtractUntilEoF(data);
	auto encrypted_data = EncryptHelper(std::span<const std::byte>(data.data(), data.size()), password);
	if (!encrypted_data.has_value()) {
		producer.SetError();
	}
	else {
		(void)producer.Write(std::move(encrypted_data.value()));
		producer.Close();
	}
	return producer.Consumer();
}

ExpectedCryptoBuffer AES_GCM::Decrypt(const std::string& encryptedData, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(encryptedData.data()), encryptedData.size());
	return DecryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer AES_GCM::Decrypt(const FIFO& encryptedData, const std::string& password) noexcept {
	DataType data;
	auto read_ok = encryptedData.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(CrypterException("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return DecryptHelper(dataSpan, password);
}

Consumer AES_GCM::Decrypt(Consumer consumer, const std::string& password) noexcept {
	/** AES-GCM does not support stream so we extract all data at once and call block helpers */
	DataType data;
	consumer.ExtractUntilEoF(data);
	Producer producer;
	auto decrypted_data = DecryptHelper(std::span<const std::byte>(data.data(), data.size()), password);
	if (!decrypted_data.has_value()) {
		producer.SetError();
	}
	else {
		(void)producer.Write(std::move(decrypted_data.value()));
		producer.Close();
	}
	return producer.Consumer();
}

ExpectedCryptoString AES_GCM::RandomPassword(size_t size) noexcept {
	try {
		CryptoPP::SecByteBlock password(size);
		RNG().GenerateBlock(password, password.size());

		std::string passwordStr;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(passwordStr));
		encoder.Put(password, password.size());
		encoder.MessageEnd();

		return passwordStr;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
	}
}
