#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/random.hxx>

#include <rsa.h>

using namespace StormByte::Crypto::KeyPair;

RSA::PointerType RSA::Generate(unsigned short key_size) noexcept {
    // Accept common RSA sizes
    if (key_size != 1024 && key_size != 2048 && key_size != 3072 && key_size != 4096)
        return nullptr;

    try {
        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(RNG(), key_size);

        CryptoPP::RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);

        return std::make_shared<RSA>(
            SerializeKey<CryptoPP::RSA::PublicKey>(publicKey),
            SerializeKey<CryptoPP::RSA::PrivateKey>(privateKey)
        );
    } catch (...) {
        return nullptr;
    }
}
