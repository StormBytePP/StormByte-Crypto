#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/keypair.hxx>
#include <StormByte/expected.hxx>

#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
    /**
     * @class Signer
     * @brief A class for managing digital signing and signature verification.
     *
     * This class provides methods for creating digital signatures and verifying them using various signing algorithms.
     */
    class STORMBYTE_CRYPTO_PUBLIC Signer final {
        public:
            /**
             * @brief Constructs a Signer instance with a specified algorithm and key pair.
             * 
             * This constructor initializes the `Signer` instance with the specified signing algorithm
             * and a key pair. The key pair is used for signing and verifying operations.
             * 
             * @param algorithm The signing algorithm to use.
             * @param keypair The key pair to use for signing and verifying.
             */
            explicit Signer(const Algorithm::Sign& algorithm, const KeyPair& keypair) noexcept;

            /**
             * @brief Constructs a Signer instance with a specified algorithm and key pair (move version).
             * 
             * This constructor initializes the `Signer` instance with the specified signing algorithm
             * and a key pair. The key pair is moved into the instance to avoid unnecessary copying.
             * 
             * @param algorithm The signing algorithm to use.
             * @param keypair The key pair to use for signing and verifying (rvalue reference).
             */
            explicit Signer(const Algorithm::Sign& algorithm, KeyPair&& keypair) noexcept;

            /**
             * @brief Copy constructor for the Signer class.
             * 
             * Creates a copy of the given `Signer` instance.
             * 
             * @param signer The `Signer` instance to copy.
             */
            Signer(const Signer& signer) 					= default;

            /**
             * @brief Move constructor for the Signer class.
             * 
             * Moves the given `Signer` instance into the current instance.
             * 
             * @param signer The `Signer` instance to move.
             */
            Signer(Signer&& signer) noexcept 				= default;

            /**
             * @brief Destructor for the Signer class.
             * 
             * Cleans up the `Signer` instance.
             */
            ~Signer() noexcept 								= default;

            /**
             * @brief Copy assignment operator for the Signer class.
             * 
             * Assigns the values from the given `Signer` instance to the current instance.
             * 
             * @param signer The `Signer` instance to copy.
             * @return A reference to the updated `Signer` instance.
             */
            Signer& operator=(const Signer& signer) 		= default;

            /**
             * @brief Move assignment operator for the Signer class.
             * 
             * Moves the values from the given `Signer` instance to the current instance.
             * 
             * @param signer The `Signer` instance to move.
             * @return A reference to the updated `Signer` instance.
             */
            Signer& operator=(Signer&& signer) noexcept 	= default;

            /**
             * @brief Signs a string input using the specified signing algorithm.
             * 
             * This method creates a digital signature for the given string input.
             * 
             * @param input The string to sign.
             * @return An Expected containing the digital signature or an error.
             */
            [[nodiscard]]
            Expected<std::string, Exception>				Sign(const std::string& input) const noexcept;

            /**
             * @brief Signs a buffer using the specified signing algorithm.
             * 
             * This method creates a digital signature for the given buffer.
             * 
             * @param buffer The buffer to sign.
             * @return An Expected containing the digital signature or an error.
             */
            [[nodiscard]]
            Expected<std::string, Exception>				Sign(const Buffer::Simple& buffer) const noexcept;

            /**
             * @brief Signs data asynchronously using a Consumer/Producer model.
             * 
             * This method creates a digital signature for the data provided by the Consumer buffer.
             * 
             * @param consumer The Consumer buffer containing the input data.
             * @return A Consumer buffer containing the digital signature.
             */
            [[nodiscard]]
            Buffer::Consumer 								Sign(const Buffer::Consumer consumer) const noexcept;

            /**
             * @brief Verifies a digital signature for a string message.
             * 
             * This method verifies the digital signature of the given string message.
             * 
             * @param message The original message.
             * @param signature The digital signature to verify.
             * @return `true` if the signature is valid, `false` otherwise.
             */
            bool 											Verify(const std::string& message, const std::string& signature) const noexcept;

            /**
             * @brief Verifies a digital signature for a buffer.
             * 
             * This method verifies the digital signature of the given buffer.
             * 
             * @param buffer The original buffer.
             * @param signature The digital signature to verify.
             * @return `true` if the signature is valid, `false` otherwise.
             */
            bool 											Verify(const Buffer::Simple& buffer, const std::string& signature) const noexcept;

            /**
             * @brief Verifies a digital signature for data provided by a Consumer buffer.
             * 
             * This method verifies the digital signature of the data provided by the Consumer buffer.
             * 
             * @param consumer The Consumer buffer containing the original data.
             * @param signature The digital signature to verify.
             * @return `true` if the signature is valid, `false` otherwise.
             */
            bool 											Verify(const Buffer::Consumer consumer, const std::string& signature) const noexcept;

        private:
            Algorithm::Sign m_algorithm;					///< The signing algorithm to use.
            class KeyPair m_keys;							///< The key pair used for signing and verifying.
    };
};