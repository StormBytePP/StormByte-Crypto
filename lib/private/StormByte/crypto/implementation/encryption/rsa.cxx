#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/implementation/encryption/rsa.hxx>

#include <algorithm>
#include <cryptlib.h>
#include <base64.h>
#include <filters.h>
#include <format>
#include <rsa.h>
#include <secblock.h>
#include <string>
#include <thread>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
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
		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(RNG(), keyStrength);

		CryptoPP::RSA::PublicKey publicKey;
		publicKey.AssignFrom(privateKey);

		KeyPair keyPair{
			.Private = SerializeKey(privateKey),
			.Public = SerializeKey(publicKey),
		};

		return keyPair;
	} catch (const std::exception& e) {
		return Unexpected(KeyPairException("Failed to generate RSA keys: {}", e.what()));
	}
}

// Encryption
ExpectedCryptoString RSA::Encrypt(const std::string& message, const std::string& publicKey) noexcept {
	try {
		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Public key validation failed"));
		}

		// Initialize the encryptor
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

		// Perform encryption
		std::string encryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(message.data()),
			message.size(),
			true,
			new CryptoPP::PK_EncryptorFilter(
				RNG(),
				encryptor,
				new CryptoPP::StringSink(encryptedMessage)
			)
		);

		return encryptedMessage;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException("RSA encryption failed: {}", e.what()));
	}
}

ExpectedCryptoBuffer RSA::Encrypt(const FIFO& input, const std::string& publicKey) noexcept {
	try {
		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Public key validation failed"));
		}

		// Initialize the encryptor
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

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
		return Unexpected(CrypterException("RSA encryption failed: {}", e.what()));
	}
}

Consumer RSA::Encrypt(Consumer consumer, const std::string& publicKey) noexcept {
	Producer producer;

	std::thread([consumer, producer, publicKey]() mutable {
		try {
			// Deserialize and validate the public key
			CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
			if (!key.Validate(RNG(), 3)) {
				producer.SetError();
				return;
			}

			// Initialize the encryptor
			CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

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
				auto readResult = consumer.Extract(bytesToRead, data);
				if (!readResult.has_value()) {
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
			producer.Close(); // Mark processing complete // Pass the status of the consumer to the producer
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

// Decryption
ExpectedCryptoString RSA::Decrypt(const std::string& message, const std::string& privateKey) noexcept {
	try {
		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Private key validation failed"));
		}

		// Initialize the decryptor
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

		// Perform decryption
		std::string decryptedMessage;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(message.data()),
			message.size(),
			true,
			new CryptoPP::PK_DecryptorFilter(
				RNG(),
				decryptor,
				new CryptoPP::StringSink(decryptedMessage)
			)
		);

		return decryptedMessage;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException("RSA decryption failed: {}", e.what()));
	}
}

ExpectedCryptoBuffer RSA::Decrypt(const FIFO& encryptedBuffer, const std::string& privateKey) noexcept {
	try {
		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(CrypterException("Private key validation failed"));
		}

		// Initialize the decryptor
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

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
		return Unexpected(CrypterException("RSA decryption failed: {}", e.what()));
	}
}

Consumer RSA::Decrypt(Consumer consumer, const std::string& privateKey) noexcept {
	Producer producer;

	std::thread([consumer, producer, privateKey]() mutable {
		try {
			// Deserialize and validate the private key
			CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(RNG(), 3)) {
				producer.SetError();
				return;
			}

		// Initialize the decryptor
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

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
		producer.Close(); // Mark processing complete // Pass the status of the consumer to the producer
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

// Signing
ExpectedCryptoString RSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
	try {
		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(SignerException("Private key validation failed"));
		}

		// Initialize the signer
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

		// Sign the message
		std::string signature;
		CryptoPP::StringSource ss(
			message,
			true,
			new CryptoPP::SignerFilter(
				RNG(),
				signer,
				new CryptoPP::StringSink(signature)
			)
		);

		return signature;
	} catch (const std::exception& e) {
		return Unexpected(SignerException("RSA signing failed: {}", e.what()));
	}
}

ExpectedCryptoBuffer RSA::Sign(const FIFO& message, const std::string& privateKey) noexcept {
	try {
		// Deserialize and validate the private key
		CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(SignerException("Private key validation failed"));
		}

		// Initialize the signer
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

		// Sign the message
		DataType data;
		auto read_ok = message.Read(data);
		if (!read_ok.has_value()) {
			return Unexpected(SignerException("Failed to extract data from message buffer"));
		}
		std::string signature;
		CryptoPP::StringSource(
			reinterpret_cast<const CryptoPP::byte*>(data.data()),
			data.size(),
			true,
			new CryptoPP::SignerFilter(
				RNG(),
				signer,
				new CryptoPP::StringSink(signature)
			)
		);

		FIFO buffer;
		(void)buffer.Write(std::move(signature));
		return buffer;
	} catch (const std::exception& e) {
		return Unexpected(SignerException("RSA signing failed: {}", e.what()));
	}
}

Consumer RSA::Sign(Consumer consumer, const std::string& privateKey) noexcept {
	Producer producer;

	std::thread([consumer, producer, privateKey]() mutable {
		try {
			// Deserialize and validate the private key
			CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(RNG(), 3)) {
				producer.SetError();
				return;
			}

			// Initialize the signer
			CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

			constexpr size_t chunkSize = 4096;

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				std::string signatureChunk;
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto spanResult = consumer.Extract(bytesToRead, data);
				if (!spanResult.has_value()) {
					producer.SetError();
					return;
				}

				// Sign the chunk
				CryptoPP::StringSource ss(
					reinterpret_cast<const CryptoPP::byte*>(data.data()),
					data.size(),
					true,
					new CryptoPP::SignerFilter(
						RNG(),
						signer,
						new CryptoPP::StringSink(signatureChunk)
					)
				);

				(void)producer.Write(std::move(signatureChunk));
			}
			producer.Close(); // Mark processing complete // Pass the status of the consumer to the producer
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

// Verification
bool RSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
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
	} catch (...) {
		return false; // Other errors
	}
}

bool RSA::Verify(const FIFO& message, const std::string& signature, const std::string& publicKey) noexcept {
	DataType data;
	auto read_ok = message.Read(data);
	if (!read_ok.has_value()) {
		return false;
	}
	return Verify(std::string(reinterpret_cast<const char*>(data.data()), data.size()), signature, publicKey);
}

bool RSA::Verify(Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Deserialize and validate the public key
		CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(key);

		const constexpr size_t chunkSize = 4096;
		bool verificationResult = false;

		while (!consumer.EoF()) {
			size_t availableBytes = consumer.AvailableBytes();
			if (availableBytes == 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				continue;
			}

			size_t bytesToRead = std::min(availableBytes, chunkSize);
			DataType data;
			auto spanResult = consumer.Extract(bytesToRead, data);
			if (!spanResult.has_value()) {
				return false; // Error reading data
			}

			// Verify the chunk
			CryptoPP::StringSource ss(
				signature + std::string(reinterpret_cast<const char*>(data.data()), data.size()),
				true,
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