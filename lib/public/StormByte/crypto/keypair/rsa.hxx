#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

namespace StormByte::Crypto::KeyPair {
    class STORMBYTE_CRYPTO_PUBLIC RSA final: public Generic {
    public:
        inline RSA(const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
        Generic(Type::RSA, public_key, private_key) {}

        RSA(const RSA& other) = default;
        RSA(RSA&& other) noexcept = default;
        ~RSA() noexcept = default;
        RSA& operator=(const RSA& other) = default;
        RSA& operator=(RSA&& other) noexcept = default;

        PointerType Clone() const noexcept override { return std::make_shared<RSA>(*this); }
        PointerType Move() noexcept override { return std::make_shared<RSA>(std::move(*this)); }

        static PointerType Generate(unsigned short key_size = 2048) noexcept;
    };
}
