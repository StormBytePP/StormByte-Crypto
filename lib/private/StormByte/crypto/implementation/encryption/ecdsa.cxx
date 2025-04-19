#include <StormByte/crypto/implementation/encryption/ecdsa.hxx>

#include <cryptlib.h>
#include <base64.h>
#include <eccrypto.h>
#include <osrng.h>
#include <oids.h>
#include <filters.h>
#include <string>
#include <future>
#include <iostream>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
    std::string SerializeKey(const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    std::string SerializeKey(const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey DeserializePublicKey(const std::string& keyString) {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key
        return key;
    }

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey DeserializePrivateKey(const std::string& keyString) {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key
        return key;
    }
}

ExpectedKeyPair ECDSA::GenerateKeyPair(const std::string& curveName) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Select the curve
        CryptoPP::OID curve = CryptoPP::ASN1::secp256r1();
        if (curveName == "secp384r1") {
            curve = CryptoPP::ASN1::secp384r1();
        } else if (curveName == "secp521r1") {
            curve = CryptoPP::ASN1::secp521r1();
        }

        // Generate the private key
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
        privateKey.Initialize(rng, curve);

        // Generate the public key
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        // Validate the keys
        if (!privateKey.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }
        if (!publicKey.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Public key validation failed");
        }

        // Serialize the keys
        std::string serializedPrivateKey = SerializeKey(privateKey);
        std::string serializedPublicKey = SerializeKey(publicKey);

        // Return the key pair
        return KeyPair{
            .Private = serializedPrivateKey,
            .Public = serializedPublicKey,
        };
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>("Unexpected error during key generation: " + std::string(e.what()));
    }
}

ExpectedCryptoFutureString ECDSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the private key
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key = DeserializePrivateKey(privateKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }

        // Initialize the signer
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);

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
        return StormByte::Unexpected<Exception>("ECDSA signing failed: " + std::string(e.what()));
    }
}

bool ECDSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);

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