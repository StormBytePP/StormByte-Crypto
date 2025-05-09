#include <StormByte/crypto/implementation/encryption/rsa.hxx>

#include <cryptlib.h>
#include <base64.h>
#include <filters.h>
#include <format>
#include <osrng.h>
#include <rsa.h>
#include <secblock.h>
#include <string>
#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	std::string SerializeKey(const CryptoPP::RSA::PrivateKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	std::string SerializeKey(const CryptoPP::RSA::PublicKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	CryptoPP::RSA::PublicKey DeserializePublicKey(const std::string& keyString) {
		CryptoPP::RSA::PublicKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key
		return key;
	}

	CryptoPP::RSA::PrivateKey DeserializePrivateKey(const std::string& keyString) {
		CryptoPP::RSA::PrivateKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key
		return key;
	}
}

// Key Pair Generation
ExpectedKeyPair RSA::GenerateKeyPair(const int& keyStrength) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(rng, keyStrength);

		CryptoPP::RSA::PublicKey publicKey;
		publicKey.AssignFrom(privateKey);

		KeyPair keyPair{
			.Private = SerializeKey(privateKey),
			.Public = SerializeKey(publicKey),
		};

		return keyPair;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("Failed to generate RSA keys: {}", e.what());
	}
}

// Encryption
ExpectedCryptoFutureString RSA::Encrypt(const std::string& message, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Public key validation failed");
		}

		// Initialize the encryptor
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

		// Perform encryption
		std::string encryptedMessage;
		CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(message.data()), message.size(), true,
								new CryptoPP::PK_EncryptorFilter(rng, encryptor,
																new CryptoPP::StringSink(encryptedMessage)));

		return encryptedMessage;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("RSA encryption failed: " + std::string(e.what()));
	}
}

ExpectedCryptoFutureBuffer RSA::Encrypt(const Buffer::Simple& input, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Public key validation failed");
		}

		// Initialize the encryptor
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

		// Perform encryption
		std::string encryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(input.Data().data()), input.Size(), true,
			new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(encryptedMessage))
		);

		// Convert the encrypted message to a buffer
		std::vector<std::byte> encryptedBuffer(encryptedMessage.size());
		std::transform(encryptedMessage.begin(), encryptedMessage.end(), encryptedBuffer.begin(),
					[](char c) { return static_cast<std::byte>(c); });

		std::promise<StormByte::Buffer::Simple> promise;
		promise.set_value(StormByte::Buffer::Simple(std::move(encryptedBuffer)));
		return promise.get_future();
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("RSA encryption failed: " + std::string(e.what()));
	}
}

StormByte::Buffer::Consumer RSA::Encrypt(const Buffer::Consumer consumer, const std::string& publicKey) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, publicKey]() {
		try {
			CryptoPP::AutoSeededRandomPool rng;

			// Deserialize and validate the public key
			CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
			if (!key.Validate(rng, 3)) {
				*producer << StormByte::Buffer::Status::Error;
				return;
			}

			// Initialize the encryptor
			CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

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
			*producer << consumer.Status(); // Pass the status of the consumer to the producer
		} catch (...) {
			*producer << StormByte::Buffer::Status::Error;
		}
	}).detach();

	return producer->Consumer();
}

// Decryption
ExpectedCryptoFutureString RSA::Decrypt(const std::string& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the decryptor
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

		// Perform decryption
		std::string decryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(message.data()), message.size(), true,
			new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedMessage))
		);

		return decryptedMessage;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("RSA decryption failed: " + std::string(e.what()));
	}
}

ExpectedCryptoFutureBuffer RSA::Decrypt(const Buffer::Simple& encryptedBuffer, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the decryptor
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

		// Perform decryption
		std::string decryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(encryptedBuffer.Data().data()), encryptedBuffer.Size(), true,
			new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedMessage))
		);

		// Convert the decrypted message to a buffer
		std::vector<std::byte> decryptedBuffer(decryptedMessage.size());
		std::transform(decryptedMessage.begin(), decryptedMessage.end(), decryptedBuffer.begin(),
					[](char c) { return static_cast<std::byte>(c); });

		std::promise<StormByte::Buffer::Simple> promise;
		promise.set_value(StormByte::Buffer::Simple(std::move(decryptedBuffer)));
		return promise.get_future();
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("RSA decryption failed: " + std::string(e.what()));
	}
}

StormByte::Buffer::Consumer RSA::Decrypt(const Buffer::Consumer consumer, const std::string& privateKey) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, privateKey]() {
		try {
			CryptoPP::AutoSeededRandomPool rng;

			// Deserialize and validate the private key
			CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(rng, 3)) {
				*producer << StormByte::Buffer::Status::Error;
				return;
			}

			// Initialize the decryptor
			CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

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
			*producer << consumer.Status(); // Pass the status of the consumer to the producer
		} catch (...) {
			*producer << StormByte::Buffer::Status::Error;
		}
	}).detach();

	return producer->Consumer();
}

// Signing
ExpectedCryptoFutureString RSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the signer
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

		// Sign the message
		std::string signature;
		CryptoPP::StringSource ss(
			message, true,
			new CryptoPP::SignerFilter(
				rng, signer,
				new CryptoPP::StringSink(signature)
			)
		);

		return signature;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("RSA signing failed: " + std::string(e.what()));
	}
}

ExpectedCryptoFutureBuffer RSA::Sign(const Buffer::Simple& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the signer
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

		// Sign the message
		std::string signature;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(message.Data().data()), message.Size(), true,
			new CryptoPP::SignerFilter(rng, signer, new CryptoPP::StringSink(signature))
		);

		// Convert the signature to a buffer
		std::vector<std::byte> signatureBuffer(signature.size());
		std::transform(signature.begin(), signature.end(), signatureBuffer.begin(),
					[](char c) { return static_cast<std::byte>(c); });

		std::promise<StormByte::Buffer::Simple> promise;
		promise.set_value(StormByte::Buffer::Simple(std::move(signatureBuffer)));
		return promise.get_future();
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("RSA signing failed: " + std::string(e.what()));
	}
}

StormByte::Buffer::Consumer RSA::Sign(const Buffer::Consumer consumer, const std::string& privateKey) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, privateKey]() {
		try {
			CryptoPP::AutoSeededRandomPool rng;

			// Deserialize and validate the private key
			CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(rng, 3)) {
				*producer << StormByte::Buffer::Status::Error;
				return;
			}

			// Initialize the signer
			CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

			constexpr size_t chunkSize = 4096;
			std::string signatureChunk;

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
				signatureChunk.clear();

				// Sign the chunk
				CryptoPP::StringSource ss(
					reinterpret_cast<const CryptoPP::byte*>(inputData.data()), inputData.size(), true,
					new CryptoPP::SignerFilter(
						rng, signer,
						new CryptoPP::StringSink(signatureChunk)
					)
				);

				*producer << StormByte::Buffer::Simple(signatureChunk.data(), signatureChunk.size());
			}
			*producer << consumer.Status(); // Pass the status of the consumer to the producer
		} catch (...) {
			*producer << StormByte::Buffer::Status::Error;
		}
	}).detach();

	return producer->Consumer();
}

// Verification
bool RSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(key);

		// Verify the signature
		bool result = false;
		CryptoPP::StringSource ss(
			signature + message, true,
			new CryptoPP::SignatureVerificationFilter(
				verifier,
				new CryptoPP::ArraySink((CryptoPP::byte*)&result, sizeof(result)),
				CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
			)
		);

		return result;
	} catch (const CryptoPP::Exception&) {
		return false; // Signature verification failed
	} catch (const std::exception&) {
		return false; // Other errors
	}
}

bool RSA::Verify(const Buffer::Simple& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(key);

		// Verify the signature
		bool result = false;
		CryptoPP::StringSource ss(
			signature + std::string(reinterpret_cast<const char*>(message.Data().data()), message.Size()), true,
			new CryptoPP::SignatureVerificationFilter(
				verifier,
				new CryptoPP::ArraySink((CryptoPP::byte*)&result, sizeof(result)),
				CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
			)
		);

		return result;
	} catch (const CryptoPP::Exception&) {
		return false; // Signature verification failed
	} catch (const std::exception&) {
		return false; // Other errors
	}
}

bool RSA::Verify(const Buffer::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(key);

		const constexpr size_t chunkSize = 4096;
		bool verificationResult = false;

		while (consumer.IsReadable() && !consumer.IsEoF()) {
			size_t availableBytes = consumer.AvailableBytes();
			if (availableBytes == 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				continue;
			}

			size_t bytesToRead = std::min(availableBytes, chunkSize);
			auto readResult = consumer.Read(bytesToRead);
			if (!readResult.has_value()) {
				return false; // Error reading data
			}

			const auto& inputData = readResult.value();

			// Verify the chunk
			CryptoPP::StringSource ss(
				signature + std::string(reinterpret_cast<const char*>(inputData.data()), inputData.size()), true,
				new CryptoPP::SignatureVerificationFilter(
					verifier,
					new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&verificationResult), sizeof(verificationResult)),
					CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
				)
			);

			if (!verificationResult) {
				return false; // Verification failed
			}
		}

		return verificationResult; // Verification succeeded
	} catch (...) {
		return false; // Handle any unexpected errors
	}
}