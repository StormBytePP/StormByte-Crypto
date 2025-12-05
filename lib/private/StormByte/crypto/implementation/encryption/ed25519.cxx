#include <StormByte/crypto/implementation/encryption/ed25519.hxx>

#include <cryptopp/osrng.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

// Ed25519 digital signature implementation
ExpectedKeyPair Ed25519::GenerateKeyPair() noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;
		
		// Generate signer; extract raw private and public key bytes
		CryptoPP::ed25519Signer signer(rng);
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
			return StormByte::Unexpected<StormByte::Crypto::Exception>("Ed25519 key hex empty after BER encoding");
		}

		return KeyPair{std::move(privateKeyStr), std::move(publicKeyStr)};
	} catch (const std::exception& e) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
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
			return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to load Ed25519 private key (BER)");
		}
		CryptoPP::ed25519Signer signer(priv);
		
		// Sign message
		CryptoPP::AutoSeededRandomPool rng;
		std::string signature;
		signature.resize(CryptoPP::ed25519Signer::SIGNATURE_LENGTH);
		signer.SignMessage(rng,
			reinterpret_cast<const uint8_t*>(message.data()), message.size(),
			reinterpret_cast<uint8_t*>(&signature[0]));
		
		// Convert to hex
		std::string hexSignature;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexSignature));
		encoder.Put(reinterpret_cast<const uint8_t*>(signature.data()), signature.size());
		encoder.MessageEnd();

		// Debug: signature length
		if (signature.size() != CryptoPP::ed25519Signer::SIGNATURE_LENGTH || hexSignature.size() != CryptoPP::ed25519Signer::SIGNATURE_LENGTH * 2) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>("Ed25519 signature length invalid");
		}
		
		return hexSignature;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
	}
}

ExpectedCryptoBuffer Ed25519::Sign(const Buffer::FIFO& message, const std::string& privateKey) noexcept {
	auto spanResult = const_cast<Buffer::FIFO&>(message).Extract(0);
	if (!spanResult.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to get span from message buffer");
	}
	
	std::string messageStr(reinterpret_cast<const char*>(spanResult.value().data()), spanResult.value().size());
	auto signatureResult = Sign(messageStr, privateKey);
	
	if (!signatureResult.has_value()) {
		return StormByte::Unexpected(signatureResult.error());
	}
	
	// Convert signature string to FIFO
	const std::string& sig = signatureResult.value();
	std::vector<std::byte> sigBytes(reinterpret_cast<const std::byte*>(sig.data()),
									reinterpret_cast<const std::byte*>(sig.data()) + sig.size());
	Buffer::FIFO fifo(std::move(sigBytes));
	return fifo;
}

StormByte::Buffer::Consumer Ed25519::Sign(Buffer::Consumer consumer, const std::string& privateKey) noexcept {
	auto producer = std::make_shared<Buffer::Producer>();
	
	std::thread([consumer, producer, privateKey]() mutable {
		try {
			// Extract all data from consumer
			auto allDataFifo = consumer.ExtractUntilEoF();
			auto spanResult = allDataFifo.Extract(0);
			if (!spanResult.has_value()) {
				producer->Close();
				return;
			}
			
			// Sign the message
			std::string message(reinterpret_cast<const char*>(spanResult.value().data()), spanResult.value().size());
			auto signatureResult = Sign(message, privateKey);
			
			if (!signatureResult.has_value()) {
				producer->Close();
				return;
			}
			
			// Write signature to producer
			const std::string& sig = signatureResult.value();
			std::vector<std::byte> sigBytes(reinterpret_cast<const std::byte*>(sig.data()),
											reinterpret_cast<const std::byte*>(sig.data()) + sig.size());
			(void)producer->Write(std::move(sigBytes));
			producer->Close();
		} catch (...) {
			producer->Close();
		}
	}).detach();
	
	return producer->Consumer();
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

bool Ed25519::Verify(const Buffer::FIFO& message, const std::string& signature, const std::string& publicKey) noexcept {
	auto spanResult = const_cast<Buffer::FIFO&>(message).Extract(0);
	if (!spanResult.has_value()) {
		return false;
	}
	
	std::string messageStr(reinterpret_cast<const char*>(spanResult.value().data()), spanResult.value().size());
	return Verify(messageStr, signature, publicKey);
}

bool Ed25519::Verify(Buffer::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Extract all data from consumer
		auto allDataFifo = consumer.ExtractUntilEoF();
		auto spanResult = allDataFifo.Extract(0);
		if (!spanResult.has_value()) {
			return false;
		}
		
		std::string message(reinterpret_cast<const char*>(spanResult.value().data()), spanResult.value().size());
		return Verify(message, signature, publicKey);
	} catch (...) {
		return false;
	}
}
