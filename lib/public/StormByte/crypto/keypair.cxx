#include <StormByte/crypto/implementation/encryption/dsa.hxx>
#include <StormByte/crypto/implementation/encryption/ecc.hxx>
#include <StormByte/crypto/implementation/encryption/ecdsa.hxx>
#include <StormByte/crypto/implementation/encryption/rsa.hxx>
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