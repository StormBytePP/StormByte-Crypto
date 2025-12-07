#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>


#include <xed25519.h>

using namespace StormByte::Crypto::KeyPair;

X25519::PointerType X25519::Generate(unsigned short key_size) noexcept {
    if (key_size != 256) return nullptr;

    // Use the generic Agreement-based keypair generator which returns
    // base64-encoded raw private/public SecByteBlock values. This keeps
    // X25519 consistent with AgreementDeriveSharedSecret which decodes
    // base64 raw blocks.
    return AgreementGenerateKeyPair<X25519, CryptoPP::x25519>();
}
