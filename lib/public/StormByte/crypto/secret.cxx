#include <StormByte/crypto/secret.hxx>
#include <StormByte/crypto/implementation/encryption/ecdh.hxx>

using namespace StormByte::Crypto;

Secret::Secret(const Algorithm::SecretShare& algorithm, const class KeyPair& key_pair) noexcept
    : m_algorithm(algorithm), m_key_pair(key_pair) {}

Secret::Secret(const Algorithm::SecretShare& algorithm, class KeyPair&& key_pair) noexcept
    : m_algorithm(algorithm), m_key_pair(std::move(key_pair)) {}

void Secret::PeerPublicKey(const std::string& peer_public_key) noexcept {
    m_peer_public_key = peer_public_key;
}

StormByte::Expected<std::string, Exception> Secret::Content() const noexcept {
    if (m_peer_public_key.empty()) {
        return StormByte::Unexpected<Exception>("Peer public key is not set.");
    }

    if (!m_key_pair.PrivateKey().has_value()) {
        return StormByte::Unexpected<Exception>("Private key is required to derive a shared secret.");
    }

    switch (m_algorithm) {
        case Algorithm::SecretShare::ECDH:
            // Derive shared secret using ECDH
            return Implementation::Encryption::ECDH::DeriveSharedSecret(m_key_pair.PrivateKey().value(), m_peer_public_key);
        default:
            return StormByte::Unexpected<Exception>("Unsupported secret-sharing algorithm.");
    }
}

const KeyPair& Secret::KeyPair() const noexcept {
    return m_key_pair;
}