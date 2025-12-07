#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/implementation/encryption/ed25519.hxx>

#include <xed25519.h>
#include <hex.h>
#include <filters.h>

#include <thread>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
using namespace StormByte::Crypto::Implementation::Encryption;

// Ed25519 digital signature implementation
ExpectedKeyPair Ed25519::GenerateKeyPair() noexcept {
	try {
		// Generate signer; extract raw private and public key bytes
		CryptoPP::ed25519Signer signer(RNG());
		auto& priv = static_cast<CryptoPP::ed25519PrivateKey&>(signer.AccessPrivateKey());
		CryptoPP::ed25519PublicKey pub;
		priv.MakePublicKey(pub);

		// Save keys in BER to ByteQueue to ensure exact bytes
		CryptoPP::ByteQueue pubQueue;
		pub.Save(pubQueue);
		CryptoPP::ByteQueue privQueue;
		priv.Save(privQueue);

		std::string privateKeyStr, publicKeyStr;
		CryptoPP::HexEncoder privEncoder(new CryptoPP::StringSink(privateKeyStr));
		{
			std::vector<unsigned char> buf(privQueue.CurrentSize());
			CryptoPP::ArraySink sink(buf.data(), buf.size());
			privQueue.CopyTo(sink);
			privEncoder.Put(buf.data(), buf.size());
		}
		privEncoder.MessageEnd();

		// Hex-encode public BER
		CryptoPP::HexEncoder pubEncoder(new CryptoPP::StringSink(publicKeyStr));        
		{
			std::vector<unsigned char> buf(pubQueue.CurrentSize());
			CryptoPP::ArraySink sink(buf.data(), buf.size());
			pubQueue.CopyTo(sink);
			pubEncoder.Put(buf.data(), buf.size());
		}
		pubEncoder.MessageEnd();


		// Debug: ensure non-empty and reasonable
		if (privateKeyStr.empty() || publicKeyStr.empty()) {
			return Unexpected(KeyPairException("Ed25519 key hex empty after BER encoding"));
		}

		return KeyPair{std::move(privateKeyStr), std::move(publicKeyStr)};
	} catch (const std::exception& e) {
		return Unexpected(KeyPairException("Unexpected error during key generation: {}", e.what()));
	}
}

ExpectedCryptoString Ed25519::Sign(const std::string& message, const std::string& privateKey) noexcept {
	try {
		// Decode private key from hex
		// Decode private key from hex (BER)
		std::string decodedKey;
		CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(decodedKey));
		decoder.Put(reinterpret_cast<const uint8_t*>(privateKey.data()), privateKey.size());
		decoder.MessageEnd();


		// Load private key from BER bytes
		CryptoPP::ed25519PrivateKey priv;
		try {
			CryptoPP::ArraySource source(reinterpret_cast<const uint8_t*>(decodedKey.data()), decodedKey.size(), true);
			priv.Load(source);
		} catch (...) {
			return Unexpected(SignerException("Failed to load Ed25519 private key (BER)"));
		}
		CryptoPP::ed25519Signer signer(priv);
		
		// Sign message
		std::string signature;
		signature.resize(CryptoPP::ed25519Signer::SIGNATURE_LENGTH);
		signer.SignMessage(RNG(),
			reinterpret_cast<const uint8_t*>(message.data()), message.size(),
			reinterpret_cast<uint8_t*>(&signature[0]));
		
		// Convert to hex
		std::string hexSignature;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexSignature));
		encoder.Put(reinterpret_cast<const uint8_t*>(signature.data()), signature.size());
		encoder.MessageEnd();

		// Debug: signature length
		if (signature.size() != CryptoPP::ed25519Signer::SIGNATURE_LENGTH || hexSignature.size() != CryptoPP::ed25519Signer::SIGNATURE_LENGTH * 2) {
			return Unexpected(SignerException("Ed25519 signature length invalid"));
		}
		
		return hexSignature;
	} catch (const std::exception& e) {
		return Unexpected(SignerException(e.what()));
	}
}

ExpectedCryptoBuffer Ed25519::Sign(const FIFO& message, const std::string& privateKey) noexcept {
	DataType data;
	auto spanResult = message.Read(data);
	if (!spanResult.has_value()) {
		return Unexpected(SignerException("Failed to get span from message buffer"));
	}
	
	std::string messageStr(reinterpret_cast<const char*>(data.data()), data.size());
	auto signatureResult = Sign(messageStr, privateKey);
	
	if (!signatureResult.has_value()) {
		return Unexpected(signatureResult.error());
	}
	
	FIFO fifo;
	fifo.Write(std::move(signatureResult.value()));
	return fifo;
}

Consumer Ed25519::Sign(Consumer consumer, const std::string& privateKey) noexcept {
	Producer producer;
	std::thread([consumer, producer, privateKey]() mutable {
		try {
			// Decode private key from hex (BER)
			std::string decodedKey;
			CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(decodedKey));
			decoder.Put(reinterpret_cast<const uint8_t*>(privateKey.data()), privateKey.size());
			decoder.MessageEnd();

			// Load private key from BER bytes
			CryptoPP::ed25519PrivateKey priv;
			try {
				CryptoPP::ArraySource source(reinterpret_cast<const uint8_t*>(decodedKey.data()), decodedKey.size(), true);
				priv.Load(source);
			} catch (...) {
				producer.Close();
				return;
			}

			CryptoPP::ed25519Signer signer(priv);

			// Prepare sink for signature (binary)
			std::string signatureBin;

			// We will own the SignerFilter and delete it after use to avoid double ownership issues
			CryptoPP::SignerFilter* filter = new CryptoPP::SignerFilter(
				RNG(),
				signer,
				new CryptoPP::StringSink(signatureBin)
			);

			// Stream-read from consumer and feed into the filter
			constexpr size_t chunkSize = 4096;
			while (!consumer.EoF()) {
				size_t available = consumer.AvailableBytes();
				if (available == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t toRead = std::min(available, chunkSize);
				DataType data;
				auto spanResult = consumer.Extract(toRead, data);
				if (!spanResult.has_value()) {
					delete filter;
					producer.SetError();
					return;
				}

				// Feed bytes into the filter
				filter->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
			}

			// Finish and collect signature
			filter->MessageEnd();

			// Delete filter (it owns the StringSink)
			delete filter;

			// Convert signature to hex
			std::string hexSignature;
			CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexSignature));
			encoder.Put(reinterpret_cast<const uint8_t*>(signatureBin.data()), signatureBin.size());
			encoder.MessageEnd();

			(void)producer.Write(std::move(hexSignature));
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();
	
	return producer.Consumer();
}

bool Ed25519::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Decode public key from hex
		std::string decodedPubKey;
		CryptoPP::HexDecoder pubDecoder(new CryptoPP::StringSink(decodedPubKey));
		pubDecoder.Put(reinterpret_cast<const uint8_t*>(publicKey.data()), publicKey.size());
		pubDecoder.MessageEnd();
		
		// Decode signature from hex
		std::string decodedSignature;
		CryptoPP::HexDecoder sigDecoder(new CryptoPP::StringSink(decodedSignature));
		sigDecoder.Put(reinterpret_cast<const uint8_t*>(signature.data()), signature.size());
		sigDecoder.MessageEnd();
		if (decodedSignature.size() != CryptoPP::ed25519Signer::SIGNATURE_LENGTH) {
			return false;
		}
		
		// Load public key from BER bytes
		CryptoPP::ed25519PublicKey pub;
		try {
			CryptoPP::ArraySource pubSource(reinterpret_cast<const uint8_t*>(decodedPubKey.data()), decodedPubKey.size(), true);
			pub.Load(pubSource);
		} catch (...) {
			return false;
		}
		CryptoPP::ed25519Verifier verifier(pub);
		
		// Verify signature using PK_Verifier API
		bool ok = verifier.VerifyMessage(
			reinterpret_cast<const uint8_t*>(message.data()), message.size(),
			reinterpret_cast<const uint8_t*>(decodedSignature.data()), decodedSignature.size());
		return ok;
	} catch (...) {
		return false;
	}
}

bool Ed25519::Verify(const FIFO& message, const std::string& signature, const std::string& publicKey) noexcept {
	DataType data;
	auto spanResult = message.Read(data);
	if (!spanResult.has_value()) {
		return false;
	}
	
	std::string messageStr(reinterpret_cast<const char*>(data.data()), data.size());
	return Verify(messageStr, signature, publicKey);
}

bool Ed25519::Verify(Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Decode public key from hex into BER bytes
		std::string decodedPubKey;
		CryptoPP::HexDecoder pubDecoder(new CryptoPP::StringSink(decodedPubKey));
		pubDecoder.Put(reinterpret_cast<const uint8_t*>(publicKey.data()), publicKey.size());
		pubDecoder.MessageEnd();

		// Decode signature from hex into raw bytes
		std::string decodedSignature;
		CryptoPP::HexDecoder sigDecoder(new CryptoPP::StringSink(decodedSignature));
		sigDecoder.Put(reinterpret_cast<const uint8_t*>(signature.data()), signature.size());
		sigDecoder.MessageEnd();
		if (decodedSignature.size() != CryptoPP::ed25519Signer::SIGNATURE_LENGTH) {
			return false;
		}

		// Load public key from BER bytes
		CryptoPP::ed25519PublicKey pub;
		try {
			CryptoPP::ArraySource pubSource(reinterpret_cast<const uint8_t*>(decodedPubKey.data()), decodedPubKey.size(), true);
			pub.Load(pubSource);
		} catch (...) {
			return false;
		}

		CryptoPP::ed25519Verifier verifier(pub);

		// Set up verification filter and result sink
		bool verificationResult = false;
		CryptoPP::SignatureVerificationFilter* filter = new CryptoPP::SignatureVerificationFilter(
			verifier,
			new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&verificationResult), sizeof(verificationResult)),
			CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
		);

		// Provide signature first (SIGNATURE_AT_BEGIN)
		filter->Put(reinterpret_cast<const CryptoPP::byte*>(decodedSignature.data()), decodedSignature.size());

		// Stream message chunks into the filter
		constexpr size_t chunkSize = 4096;
		while (!consumer.EoF()) {
			size_t available = consumer.AvailableBytes();
			if (available == 0) {
				std::this_thread::yield();
				continue;
			}

			size_t toRead = std::min(available, chunkSize);
			DataType data;
			auto read_ok = consumer.Extract(toRead, data);
			if (!read_ok.has_value()) {
				delete filter;
				return false;
			}

			filter->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
		}

		// Finalize verification
		filter->MessageEnd();
		bool result = verificationResult;
		delete filter;
		return result;
	} catch (...) {
		return false;
	}
}
