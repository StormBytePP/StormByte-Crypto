#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <xed25519.h>

using namespace StormByte::Crypto::KeyPair;

X25519::PointerType X25519::Generate(unsigned short /*bits*/) noexcept {
	try {
		CryptoPP::x25519 x;
		CryptoPP::SecByteBlock priv(x.PrivateKeyLength());
		CryptoPP::SecByteBlock pub(x.PublicKeyLength());
		x.GenerateKeyPair(RNG(), priv, pub);

		auto pubStr = Implementation::KeyPair::EncodeSecBlockBase64(pub);
		Password privPwd = Implementation::KeyPair::PasswordFromSecBlock(priv);
		Helpers::SecureWipe(pub);

		return std::make_shared<X25519>(
			std::move(pubStr),
			std::move(privPwd)
		);
	} catch (...) {
		return nullptr;
	}
}
