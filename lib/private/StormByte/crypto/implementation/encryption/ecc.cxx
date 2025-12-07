#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/implementation/encryption/ecc.hxx>

#include <algorithm>
#include <base64.h>
#include <cryptlib.h>
#include <eccrypto.h>
#include <filters.h>
#include <format>
#include <oids.h>
#include <string>
#include <thread>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;

	std::string SerializeKey(const ECIES::PrivateKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save the key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	std::string SerializeKey(const ECIES::PublicKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save the key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	ECIES::PrivateKey DeserializePrivateKey(const std::string& keyString) {
		ECIES::PrivateKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key

		// Explicitly initialize curve parameters
		key.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256r1());

		return key;
	}

	ECIES::PublicKey DeserializePublicKey(const std::string& keyString) {
		ECIES::PublicKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key

		// Explicitly initialize curve parameters
		key.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256r1());

		return key;
	}

	// Helper function to map curve names to CryptoPP::OID
	std::optional<CryptoPP::OID> GetCurveOID(const std::string& curve_name) {
		if (curve_name == "secp256r1") {
			return CryptoPP::ASN1::secp256r1();
		} else if (curve_name == "secp384r1") {
			return CryptoPP::ASN1::secp384r1();
		} else if (curve_name == "secp521r1") {
			return CryptoPP::ASN1::secp521r1();
		}
		return std::nullopt; // Unknown curve name
	}
}

ExpectedKeyPair ECC::GenerateKeyPair(const std::string& curve_name) noexcept {
	try {
		// Map curve_name to CryptoPP::OID
		auto curve_oid = GetCurveOID(curve_name);
		if (!curve_oid.has_value()) {
			return Unexpected(KeyPairException("Unknown curve name: {}", curve_name));
		}

		// Generate private key
		ECIES::PrivateKey privateKey;
		privateKey.Initialize(RNG(), curve_oid.value());

		// Generate public key
		ECIES::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		// Serialize keys
		KeyPair keyPair{
			.Private = SerializeKey(privateKey),
			.Public = SerializeKey(publicKey),
		};

		return keyPair;
	} catch (const std::exception& e) {
		return Unexpected(KeyPairException("Failed to generate ECC keys: {}", e.what()));
	}
}

ExpectedCryptoString ECC::Encrypt(const std::string& message, const std::string& publicKey) noexcept {
	try {
		// Deserialize, initialize, and validate the public key
		ECIES::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Public key validation failed"));
		}

		// Initialize the encryptor
		ECIES::Encryptor encryptor(key);

		// Perform encryption
		std::string encryptedMessage;
		CryptoPP::StringSource ss(
			message,
			true,
			new CryptoPP::PK_EncryptorFilter(
				RNG(),
				encryptor,
				new CryptoPP::StringSink(encryptedMessage)
			)
		);

		return encryptedMessage;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException("ECC encryption failed: {}", e.what()));
	}
}

ExpectedCryptoBuffer ECC::Encrypt(const FIFO& input, const std::string& publicKey) noexcept {
	try {
		// Deserialize, initialize, and validate the public key
		ECIES::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Public key validation failed"));
		}

		// Initialize the encryptor
		ECIES::Encryptor encryptor(key);

		// Perform encryption
		DataType data;
		auto read_ok = input.Read(data);
		if (!read_ok.has_value()) {
			return Unexpected(CrypterException("Failed to extract data from input buffer"));
		}
		std::string encryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(data.data()),
			data.size(),
			true,
			new CryptoPP::PK_EncryptorFilter(
				RNG(),
				encryptor,
				new CryptoPP::StringSink(encryptedMessage)
			)
		);

		FIFO buffer;
		(void)buffer.Write(std::move(encryptedMessage));
		return buffer;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException("ECC encryption failed: {}", e.what()));
	}
}

Consumer ECC::Encrypt(Consumer consumer, const std::string& publicKey) noexcept {
	Producer producer;

	std::thread([consumer, producer, publicKey]() mutable {
		try {
			// Deserialize, initialize, and validate the public key
			ECIES::PublicKey key = DeserializePublicKey(publicKey);
			if (!key.Validate(RNG(), 3)) {
				producer.SetError();
				return;
			}

			// Initialize the encryptor
			ECIES::Encryptor encryptor(key);

			constexpr size_t chunkSize = 4096;

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				std::string encryptedChunk;
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto spanResult = consumer.Extract(bytesToRead, data);
				if (!spanResult.has_value()) {
					producer.SetError();
					return;
				}

				CryptoPP::StringSource ss(
					reinterpret_cast<const CryptoPP::byte*>(data.data()),
					data.size(),
					true,
					new CryptoPP::PK_EncryptorFilter(
						RNG(),
						encryptor,
						new CryptoPP::StringSink(encryptedChunk)
					)
				);

				(void)producer.Write(std::move(encryptedChunk));
			}
			producer.Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

ExpectedCryptoString ECC::Decrypt(const std::string& message, const std::string& privateKey) noexcept {
	try {
		// Deserialize, initialize, and validate the private key
		ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Private key validation failed"));
		}

		// Initialize the decryptor
		ECIES::Decryptor decryptor(key);

		// Perform decryption
		std::string decryptedMessage;
		CryptoPP::StringSource ss(
			message,
			true,
			new CryptoPP::PK_DecryptorFilter(
				RNG(),
				decryptor,
				new CryptoPP::StringSink(decryptedMessage)
			)
		);

		return decryptedMessage;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException("ECC decryption failed: {}", e.what()));
	}
}

ExpectedCryptoBuffer ECC::Decrypt(const FIFO& encryptedBuffer, const std::string& privateKey) noexcept {
	try {
		// Deserialize, initialize, and validate the private key
		ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Private key validation failed"));
		}

		// Initialize the decryptor
		ECIES::Decryptor decryptor(key);

		// Perform decryption
		DataType data;
		auto read_ok = encryptedBuffer.Read(data);
		if (!read_ok.has_value()) {
			return Unexpected(CrypterException("Failed to extract data from encrypted buffer"));
		}
		std::string decryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(data.data()),
			data.size(),
			true,
			new CryptoPP::PK_DecryptorFilter(
				RNG(),
				decryptor,
				new CryptoPP::StringSink(decryptedMessage)
			)
		);

		FIFO buffer;
		(void)buffer.Write(std::move(decryptedMessage));
		return buffer;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException("ECC decryption failed: {}", e.what()));
	}
}

Consumer ECC::Decrypt(Consumer consumer, const std::string& privateKey) noexcept {
	Producer producer;

	std::thread([consumer, producer, privateKey]() mutable {
		try {
			// Deserialize, initialize, and validate the private key
			ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(RNG(), 3)) {
				producer.SetError();
				return;
			}

			// Initialize the decryptor
			ECIES::Decryptor decryptor(key);

			constexpr size_t chunkSize = 4096;

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				std::string decryptedChunk;
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto spanResult = consumer.Extract(bytesToRead, data);
				if (!spanResult.has_value()) {
					producer.SetError();
					return;
				}

				CryptoPP::StringSource ss(
					reinterpret_cast<const CryptoPP::byte*>(data.data()),
					data.size(),
					true,
					new CryptoPP::PK_DecryptorFilter(
						RNG(),
						decryptor,
						new CryptoPP::StringSink(decryptedChunk)
					)
				);

				(void)producer.Write(std::move(decryptedChunk));
			}
			producer.Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}