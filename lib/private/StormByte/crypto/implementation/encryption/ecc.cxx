#include <StormByte/crypto/implementation/encryption/ecc.hxx>

#include <base64.h>
#include <cryptlib.h>
#include <eccrypto.h>
#include <filters.h>
#include <format>
#include <osrng.h>
#include <oids.h>
#include <string>
#include <thread>

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
		CryptoPP::AutoSeededRandomPool rng;

		// Map curve_name to CryptoPP::OID
		auto curve_oid = GetCurveOID(curve_name);
		if (!curve_oid.has_value()) {
			return StormByte::Unexpected<Exception>("Unknown curve name: " + curve_name);
		}

		// Generate private key
		ECIES::PrivateKey privateKey;
		privateKey.Initialize(rng, curve_oid.value());

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
		return StormByte::Unexpected<Exception>("Failed to generate ECC keys: " + std::string(e.what()));
	}
}

ExpectedCryptoFutureString ECC::Encrypt(const std::string& message, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize, initialize, and validate the public key
		ECIES::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Public key validation failed");
		}

		// Initialize the encryptor
		ECIES::Encryptor encryptor(key);

		// Perform encryption
		std::string encryptedMessage;
		CryptoPP::StringSource ss(message, true,
								new CryptoPP::PK_EncryptorFilter(rng, encryptor,
																new CryptoPP::StringSink(encryptedMessage)));

		return encryptedMessage;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("ECC encryption failed: " + std::string(e.what()));
	}
}

ExpectedCryptoFutureBuffer ECC::Encrypt(const Buffer::Simple& input, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize, initialize, and validate the public key
		ECIES::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Public key validation failed");
		}

		// Initialize the encryptor
		ECIES::Encryptor encryptor(key);

		// Perform encryption
		std::string encryptedMessage;
		CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(input.Data().data()), input.Size(), true,
								new CryptoPP::PK_EncryptorFilter(rng, encryptor,
																new CryptoPP::StringSink(encryptedMessage)));

		// Convert the encrypted message into a buffer
		std::vector<std::byte> encryptedBuffer(encryptedMessage.size());
		std::transform(encryptedMessage.begin(), encryptedMessage.end(), encryptedBuffer.begin(),
					[](char c) { return static_cast<std::byte>(c); });

		std::promise<StormByte::Buffer::Simple> promise;
		promise.set_value(StormByte::Buffer::Simple(std::move(encryptedBuffer)));
		return promise.get_future();
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("ECC encryption failed: " + std::string(e.what()));
	}
}

StormByte::Buffer::Consumer ECC::Encrypt(const Buffer::Consumer consumer, const std::string& publicKey) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, publicKey]() {
		try {
			CryptoPP::AutoSeededRandomPool rng;

			// Deserialize, initialize, and validate the public key
			ECIES::PublicKey key = DeserializePublicKey(publicKey);
			if (!key.Validate(rng, 3)) {
				*producer << StormByte::Buffer::Status::Error;
				return;
			}

			// Initialize the encryptor
			ECIES::Encryptor encryptor(key);

			constexpr size_t chunkSize = 4096;
			std::string encryptedChunk;

			while (consumer.IsReadable() && !consumer.IsEoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					*producer << StormByte::Buffer::Status::Error;
					return;
				}

				const auto& inputData = readResult.value();
				encryptedChunk.clear();

				CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(inputData.data()), inputData.size(), true,
										new CryptoPP::PK_EncryptorFilter(rng, encryptor,
																		new CryptoPP::StringSink(encryptedChunk)));

				*producer << StormByte::Buffer::Simple(encryptedChunk.data(), encryptedChunk.size());
			}
			*producer << consumer.Status(); // Update status (EOF or Error)
		} catch (...) {
			*producer << StormByte::Buffer::Status::Error;
		}
	}).detach();

	return producer->Consumer();
}

ExpectedCryptoFutureString ECC::Decrypt(const std::string& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize, initialize, and validate the private key
		ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the decryptor
		ECIES::Decryptor decryptor(key);

		// Perform decryption
		std::string decryptedMessage;
		CryptoPP::StringSource ss(message, true,
								new CryptoPP::PK_DecryptorFilter(rng, decryptor,
																new CryptoPP::StringSink(decryptedMessage)));

		return decryptedMessage;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("ECC decryption failed: " + std::string(e.what()));
	}
}

ExpectedCryptoFutureBuffer ECC::Decrypt(const Buffer::Simple& encryptedBuffer, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize, initialize, and validate the private key
		ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the decryptor
		ECIES::Decryptor decryptor(key);

		// Perform decryption
		std::string decryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(encryptedBuffer.Data().data()), encryptedBuffer.Size(), true,
			new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedMessage))
		);

		// Convert the decrypted message into a buffer
		std::vector<std::byte> decryptedBuffer(decryptedMessage.size());
		std::transform(decryptedMessage.begin(), decryptedMessage.end(), decryptedBuffer.begin(),
					[](char c) { return static_cast<std::byte>(c); });

		std::promise<StormByte::Buffer::Simple> promise;
		promise.set_value(StormByte::Buffer::Simple(std::move(decryptedBuffer)));
		return promise.get_future();
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("ECC decryption failed: " + std::string(e.what()));
	}
}

StormByte::Buffer::Consumer ECC::Decrypt(const Buffer::Consumer consumer, const std::string& privateKey) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, privateKey]() {
		try {
			CryptoPP::AutoSeededRandomPool rng;

			// Deserialize, initialize, and validate the private key
			ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(rng, 3)) {
				*producer << StormByte::Buffer::Status::Error;
				return;
			}

			// Initialize the decryptor
			ECIES::Decryptor decryptor(key);

			constexpr size_t chunkSize = 4096;
			std::string decryptedChunk;

			while (consumer.IsReadable() && !consumer.IsEoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					*producer << StormByte::Buffer::Status::Error;
					return;
				}

				const auto& encryptedData = readResult.value();
				decryptedChunk.clear();

				CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(encryptedData.data()), encryptedData.size(), true,
										new CryptoPP::PK_DecryptorFilter(rng, decryptor,
																		new CryptoPP::StringSink(decryptedChunk)));

				*producer << StormByte::Buffer::Simple(decryptedChunk.data(), decryptedChunk.size());
			}
			*producer << consumer.Status(); // Update status (EOF or Error)
		} catch (...) {
			*producer << StormByte::Buffer::Status::Error;
		}
	}).detach();

	return producer->Consumer();
}