#include <StormByte/crypto/implementation/encryption/dsa.hxx>
#include <StormByte/crypto/implementation/encryption/ecc.hxx>
#include <StormByte/crypto/implementation/encryption/ecdh.hxx>
#include <StormByte/crypto/implementation/encryption/ecdsa.hxx>
#include <StormByte/crypto/implementation/encryption/rsa.hxx>
#include <StormByte/crypto/implementation/encryption/ed25519.hxx>
#include <StormByte/crypto/implementation/encryption/x25519.hxx>
#include <StormByte/crypto/keypair.hxx>

using namespace StormByte::Crypto;

KeyPair::KeyPair(const std::string& pub, const std::string& priv) noexcept
	: m_public_key(pub), m_private_key(priv) {}

KeyPair::KeyPair(std::string&& pub, std::string&& priv) noexcept
	: m_public_key(std::move(pub)), m_private_key(std::move(priv)) {}

KeyPair::KeyPair(const std::string& pub) noexcept
	: m_public_key(pub), m_private_key(std::nullopt) {}

KeyPair::KeyPair(std::string&& pub) noexcept
	: m_public_key(std::move(pub)), m_private_key(std::nullopt) {}

const std::string& KeyPair::PublicKey() const noexcept {
	return m_public_key;
}

const std::optional<std::string>& KeyPair::PrivateKey() const noexcept {
	return m_private_key;
}

// Generate KeyPair for Asymmetric Algorithms with default key size/curve name
StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Asymmetric& algorithm) noexcept {
	switch(algorithm) {
		case Algorithm::Asymmetric::ECC: {
			return Generate(algorithm, "secp256r1");
		}
		case Algorithm::Asymmetric::RSA: {
			return Generate(algorithm, 2048);
		}
		default:
			return StormByte::Unexpected<Exception>("Invalid asymmetric algorithm.");
	}
}

// Generate KeyPair for Asymmetric Algorithms
StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Asymmetric& algorithm, const size_t& key_size) noexcept {
	std::optional<Implementation::Encryption::ExpectedKeyPair> key_pair;

	switch (algorithm) {
		case Algorithm::Asymmetric::ECC:
			// ECC supports curve_name, not key_size
			return StormByte::Unexpected<Exception>("ECC does not support key_size. Use curve_name instead.");
		case Algorithm::Asymmetric::RSA:
			// RSA supports key_size
			key_pair = Implementation::Encryption::RSA::GenerateKeyPair(key_size);
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for key_size.");
	}

	// Check if key generation succeeded
	if (key_pair->has_value()) {
		return KeyPair(std::move(key_pair->value().Public), std::move(key_pair->value().Private));
	} else {
		return StormByte::Unexpected(key_pair->error());
	}
}

StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Asymmetric& algorithm, const std::string& curve_name) noexcept {
	std::optional<Implementation::Encryption::ExpectedKeyPair> key_pair;

	switch (algorithm) {
		case Algorithm::Asymmetric::ECC:
			// ECC supports curve_name
			key_pair = Implementation::Encryption::ECC::GenerateKeyPair(curve_name);
			break;
		case Algorithm::Asymmetric::RSA:
			// RSA supports key_size, not curve_name
			return StormByte::Unexpected<Exception>("RSA does not support curve_name. Use key_size instead.");
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for curve_name.");
	}

	// Check if key generation succeeded
	if (key_pair->has_value()) {
		return KeyPair(std::move(key_pair->value().Public), std::move(key_pair->value().Private));
	} else {
		return StormByte::Unexpected(key_pair->error());
	}
}

// Generate KeyPair for Signing Algorithms with default key size/curve name
StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Sign& algorithm) noexcept {
	switch(algorithm) {
		case Algorithm::Sign::DSA: {
			return Generate(algorithm, 2048);
		}
		case Algorithm::Sign::RSA: {
			return Generate(algorithm, 2048);
		}
		case Algorithm::Sign::ECDSA: {
			return Generate(algorithm, "secp256r1");
		}
		case Algorithm::Sign::Ed25519: {
			// Ed25519 has fixed parameters, no curve name needed
			auto key_pair = Implementation::Encryption::Ed25519::GenerateKeyPair();
			if (key_pair.has_value()) {
				return KeyPair(std::move(key_pair->Public), std::move(key_pair->Private));
			} else {
				return StormByte::Unexpected(key_pair.error());
			}
		}
		default:
			return StormByte::Unexpected<Exception>("Invalid signing algorithm.");
	}
}

// Generate KeyPair for Signing Algorithms
StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Sign& algorithm, const size_t& key_size) noexcept {
	std::optional<Implementation::Encryption::ExpectedKeyPair> key_pair;

	switch (algorithm) {
		case Algorithm::Sign::DSA:
			// DSA supports key_size
			key_pair = Implementation::Encryption::DSA::GenerateKeyPair(key_size);
			break;
		case Algorithm::Sign::RSA:
			// RSA supports key_size
			key_pair = Implementation::Encryption::RSA::GenerateKeyPair(key_size);
			break;
		case Algorithm::Sign::ECDSA:
			// ECDSA supports curve_name, not key_size
			return StormByte::Unexpected<Exception>("ECDSA does not support key_size. Use curve_name instead.");
		case Algorithm::Sign::Ed25519:
			// Ed25519 has fixed key size, no parameters needed
			key_pair = Implementation::Encryption::Ed25519::GenerateKeyPair();
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid signing algorithm for key_size.");
	}

	// Check if key generation succeeded
	if (key_pair->has_value()) {
		return KeyPair(std::move(key_pair->value().Public), std::move(key_pair->value().Private));
	} else {
		return StormByte::Unexpected(key_pair->error());
	}
}

StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Sign& algorithm, const std::string& curve_name) noexcept {
	std::optional<Implementation::Encryption::ExpectedKeyPair> key_pair;

	switch (algorithm) {
		case Algorithm::Sign::ECDSA:
			// ECDSA supports curve_name
			key_pair = Implementation::Encryption::ECDSA::GenerateKeyPair(curve_name);
			break;
		case Algorithm::Sign::DSA:
			// DSA supports key_size, not curve_name
			return StormByte::Unexpected<Exception>("DSA does not support curve_name. Use key_size instead.");
		case Algorithm::Sign::RSA:
			// RSA supports key_size, not curve_name
			return StormByte::Unexpected<Exception>("RSA does not support curve_name. Use key_size instead.");
		case Algorithm::Sign::Ed25519:
			// Ed25519 has fixed parameters, doesn't need curve_name
			return StormByte::Unexpected<Exception>("Ed25519 does not support curve_name. Use no parameters instead.");
		default:
			return StormByte::Unexpected<Exception>("Invalid signing algorithm for curve_name.");
	}

	// Check if key generation succeeded
	if (key_pair->has_value()) {
		return KeyPair(std::move(key_pair->value().Public), std::move(key_pair->value().Private));
	} else {
		return StormByte::Unexpected(key_pair->error());
	}
}

// Generate KeyPair for Secret Sharing Algorithms with default curve name
StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::SecretShare& algorithm) noexcept {
	switch(algorithm) {
		case Algorithm::SecretShare::ECDH: {
			return Generate(algorithm, "secp256r1");
		}
		case Algorithm::SecretShare::X25519: {
			// X25519 has fixed curve (Curve25519), use no-parameter version
			auto key_pair = Implementation::Encryption::X25519::GenerateKeyPair();
			if (key_pair.has_value()) {
				return KeyPair(std::move(key_pair.value().Public), std::move(key_pair.value().Private));
			} else {
				return StormByte::Unexpected(key_pair.error());
			}
		}
		default:
			return StormByte::Unexpected<Exception>("Invalid secret-sharing algorithm.");
	}
}

// Generate KeyPair for Secret Sharing Algorithms
StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::SecretShare& algorithm, const std::string& curve_name) noexcept {
	try {
		switch (algorithm) {
			case Algorithm::SecretShare::ECDH: {
				// Call the ECDH implementation to generate the key pair
				auto key_pair = Implementation::Encryption::ECDH::GenerateKeyPair(curve_name);
				if (!key_pair.has_value()) {
					return StormByte::Unexpected(key_pair.error());
				}
				return KeyPair(std::move(key_pair->Public), std::move(key_pair->Private));
			}
		case Algorithm::SecretShare::X25519: {
			// X25519 has fixed curve, doesn't need curve_name parameter
			auto key_pair = Implementation::Encryption::X25519::GenerateKeyPair();
			if (!key_pair.has_value()) {
				return StormByte::Unexpected(key_pair.error());
			}
			return KeyPair(std::move(key_pair->Public), std::move(key_pair->Private));
		}
			default:
				return StormByte::Unexpected<Exception>("Unsupported algorithm for key pair generation.");
		}
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("Unexpected error during key pair generation: " + std::string(e.what()));
	}
}
