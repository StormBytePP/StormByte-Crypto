#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/random.hxx>

#include <xed25519.h>

using namespace StormByte::Crypto::KeyPair;

ED25519::PointerType ED25519::Generate(unsigned short key_size) noexcept {
	// ED25519 uses a fixed 256-bit curve; reject other sizes
	if (key_size != 256) return nullptr;

	try {
		// Create a signer to generate a private key, then extract the key objects
		CryptoPP::ed25519Signer signer(RNG());
		auto& priv = static_cast<CryptoPP::ed25519PrivateKey&>(signer.AccessPrivateKey());

		CryptoPP::ed25519PublicKey pub;
		priv.MakePublicKey(pub);

		return std::make_shared<ED25519>(
			SerializeKey<CryptoPP::ed25519PublicKey>(pub),
			SerializeKey<CryptoPP::ed25519PrivateKey>(priv)
		);
	} catch (...) {
		return nullptr;
	}
}
