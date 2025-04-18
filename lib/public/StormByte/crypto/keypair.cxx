#include <StormByte/crypto/implementation/encryption/dsa.hxx>
#include <StormByte/crypto/implementation/encryption/ecc.hxx>
#include <StormByte/crypto/implementation/encryption/rsa.hxx>
#include <StormByte/crypto/keypair.hxx>

using namespace StormByte::Crypto;

KeyPair::KeyPair(const std::string& pub, const std::string& priv) noexcept
:m_public_key(pub), m_private_key(priv) {}

KeyPair::KeyPair(std::string&& pub, std::string&& priv) noexcept
:m_public_key(std::move(pub)), m_private_key(std::move(priv)) {}

KeyPair::KeyPair(const std::string& pub) noexcept
:m_public_key(pub), m_private_key(std::nullopt) {}

KeyPair::KeyPair(std::string&& pub) noexcept
:m_public_key(std::move(pub)), m_private_key(std::nullopt) {}

const std::string& KeyPair::PublicKey() const noexcept {
	return m_public_key;
}

const std::optional<std::string>& KeyPair::PrivateKey() const noexcept {
	return m_private_key;
}

StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Asymmetric& algorithm, const size_t& key_size) noexcept {
	std::optional<Implementation::Encryption::ExpectedKeyPair> key_pair;
	switch(algorithm) {
		case Algorithm::Asymmetric::ECC:
			key_pair = Implementation::Encryption::ECC::GenerateKeyPair(key_size);
			break;
		case Algorithm::Asymmetric::RSA:
			key_pair = Implementation::Encryption::RSA::GenerateKeyPair(key_size);
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm");
	}

	// The optional always have value as default returns but the key generation can fail
	if (key_pair->has_value()) {
		return KeyPair(std::move(key_pair->value().Public), std::move(key_pair->value().Private));
	} else {
		return StormByte::Unexpected(key_pair->error());
	}
}

StormByte::Expected<KeyPair, Exception> KeyPair::Generate(const Algorithm::Sign& algorithm, const size_t& key_size) noexcept {
	std::optional<Implementation::Encryption::ExpectedKeyPair> key_pair;
	switch(algorithm) {
		case Algorithm::Sign::DSA:
			key_pair = Implementation::Encryption::DSA::GenerateKeyPair(key_size);
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm");
	}

	// The optional always have value as default returns but the key generation can fail
	if (key_pair->has_value()) {
		return KeyPair(std::move(key_pair->value().Public), std::move(key_pair->value().Private));
	} else {
		return StormByte::Unexpected(key_pair->error());
	}
}