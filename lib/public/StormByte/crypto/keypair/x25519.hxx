#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

namespace StormByte::Crypto::KeyPair {
    class STORMBYTE_CRYPTO_PUBLIC X25519 final: public Generic {
    public:
        inline X25519(const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
        Generic(Type::X25519, public_key, private_key) {}

        X25519(const X25519& other) = default;
        X25519(X25519&& other) noexcept = default;
        ~X25519() noexcept = default;
        X25519& operator=(const X25519& other) = default;
        X25519& operator=(X25519&& other) noexcept = default;

        PointerType Clone() const noexcept override { return std::make_shared<X25519>(*this); }
        PointerType Move() noexcept override { return std::make_shared<X25519>(std::move(*this)); }

        static PointerType Generate(unsigned short key_size = 256) noexcept;
    };
}
