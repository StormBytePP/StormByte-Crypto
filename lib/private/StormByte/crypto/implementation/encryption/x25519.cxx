#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/implementation/encryption/x25519.hxx>

#include <xed25519.h>
#include <hex.h>
#include <filters.h>

using namespace StormByte::Crypto::Implementation::Encryption;

// X25519 key exchange implementation (Curve25519)
ExpectedKeyPair X25519::GenerateKeyPair() noexcept {
	try {
		// Generate X25519 private key
		CryptoPP::x25519 agreement;
		CryptoPP::SecByteBlock privateKey(agreement.PrivateKeyLength());
		CryptoPP::SecByteBlock publicKey(agreement.PublicKeyLength());
		
		agreement.GenerateKeyPair(RNG(), privateKey, publicKey);
		
		// Convert to hex strings
		std::string privateKeyStr, publicKeyStr;
		CryptoPP::HexEncoder privEncoder(new CryptoPP::StringSink(privateKeyStr));
		privEncoder.Put(privateKey, privateKey.size());
		privEncoder.MessageEnd();
		
		CryptoPP::HexEncoder pubEncoder(new CryptoPP::StringSink(publicKeyStr));
		pubEncoder.Put(publicKey, publicKey.size());
		pubEncoder.MessageEnd();
		
		return KeyPair{std::move(privateKeyStr), std::move(publicKeyStr)};
	} catch (const std::exception& e) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
	}
}

ExpectedCryptoString X25519::DeriveSharedSecret(const std::string& privateKey, const std::string& peerPublicKey) noexcept {
	try {
		// Decode private key from hex
		std::string decodedPrivKey;
		CryptoPP::HexDecoder privDecoder(new CryptoPP::StringSink(decodedPrivKey));
		privDecoder.Put(reinterpret_cast<const uint8_t*>(privateKey.data()), privateKey.size());
		privDecoder.MessageEnd();
		
		// Decode peer public key from hex
		std::string decodedPubKey;
		CryptoPP::HexDecoder pubDecoder(new CryptoPP::StringSink(decodedPubKey));
		pubDecoder.Put(reinterpret_cast<const uint8_t*>(peerPublicKey.data()), peerPublicKey.size());
		pubDecoder.MessageEnd();
		
		// Perform X25519 key agreement
		CryptoPP::x25519 agreement;
		CryptoPP::SecByteBlock sharedSecret(agreement.AgreedValueLength());
		
		if (!agreement.Agree(
			sharedSecret,
			reinterpret_cast<const uint8_t*>(decodedPrivKey.data()),
			reinterpret_cast<const uint8_t*>(decodedPubKey.data()))
		) {
			return Unexpected(CrypterException("Failed to derive shared secret"));
		}
		
		// Convert shared secret to hex
		std::string hexSecret;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexSecret));
		encoder.Put(sharedSecret, sharedSecret.size());
		encoder.MessageEnd();
		
		return hexSecret;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException(e.what()));
	}
}
