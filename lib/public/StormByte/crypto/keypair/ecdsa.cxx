#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

using CryptoECDSA = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

ECDSA::PointerType ECDSA::Generate(unsigned short key_size) noexcept {
    CryptoPP::OID curve_oid;
    switch (key_size) {
        case 256:
            curve_oid = CryptoPP::ASN1::secp256r1();
            break;
        case 384:
            curve_oid = CryptoPP::ASN1::secp384r1();
            break;
        case 521:
            curve_oid = CryptoPP::ASN1::secp521r1();
            break;
        default:
            return nullptr;
    }

    try {
        // Generate private key
        CryptoECDSA::PrivateKey privateKey;
        privateKey.Initialize(RNG(), curve_oid);

        // Generate public key
        CryptoECDSA::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        // Validate
        if (!privateKey.Validate(RNG(), 3)) return nullptr;
        if (!publicKey.Validate(RNG(), 3)) return nullptr;

        return std::make_shared<ECDSA>(
            SerializeKey<CryptoECDSA::PublicKey>(publicKey),
            SerializeKey<CryptoECDSA::PrivateKey>(privateKey)
        );
    } catch (...) {
        return nullptr;
    }
}
