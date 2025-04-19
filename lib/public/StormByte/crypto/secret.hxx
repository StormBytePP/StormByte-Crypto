#pragma once

#include <StormByte/crypto/keypair.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/expected.hxx>

#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
    /**
     * @class Secret
     * @brief A class for managing shared secret operations.
     *
     * This class provides methods for generating key pairs and deriving shared secrets
     * using various secret-sharing algorithms (e.g., ECDH).
     */
    class STORMBYTE_CRYPTO_PUBLIC Secret final {
    public:
        /**
         * @brief Constructs a Secret instance with an algorithm and a key pair.
         * @param algorithm The secret-sharing algorithm to use.
         * @param key_pair The key pair to use for shared secret operations.
         */
        explicit Secret(const Algorithm::SecretShare& algorithm, const KeyPair& key_pair) noexcept;

        /**
         * @brief Constructs a Secret instance with an algorithm and a key pair (move version).
         * @param algorithm The secret-sharing algorithm to use.
         * @param key_pair The key pair to use for shared secret operations.
         */
        explicit Secret(const Algorithm::SecretShare& algorithm, KeyPair&& key_pair) noexcept;

        /**
         * @brief Sets the peer's public key for shared secret derivation.
         * @param peer_public_key The public key of the peer.
         */
        void PeerPublicKey(const std::string& peer_public_key) noexcept;

        /**
         * @brief Derives the shared secret using the private key and the peer's public key.
         * @return An Expected containing the derived shared secret or an error.
         */
        [[nodiscard]]
        Expected<std::string, Exception> Content() const noexcept;

        /**
         * @brief Returns the key pair associated with this Secret instance.
         * @return The key pair.
         */
        [[nodiscard]]
        const KeyPair& KeyPair() const noexcept;

    private:
        Algorithm::SecretShare m_algorithm; ///< The secret-sharing algorithm to use.
        class KeyPair m_key_pair;                 ///< The key pair used for shared secret operations.
        std::string m_peer_public_key;      ///< The peer's public key.
    };
}