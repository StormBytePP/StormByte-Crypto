#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <xed25519.h>
#include <queue.h>

using namespace StormByte::Crypto::KeyPair;

ED25519::PointerType ED25519::Generate(unsigned short /*bits*/) noexcept {
	try {
		CryptoPP::ed25519::Signer signer(RNG());
		CryptoPP::ed25519::Verifier verifier(signer);

		CryptoPP::ByteQueue pubQueue;
		verifier.GetPublicKey().Save(pubQueue);
		CryptoPP::SecByteBlock pub(pubQueue.CurrentSize());
		pubQueue.Get(pub.data(), pub.size());
		auto pubStr = Implementation::KeyPair::EncodeSecBlockBase64(pub);
		Helpers::SecureWipe(pub);

		CryptoPP::ByteQueue privQueue;
		signer.GetPrivateKey().Save(privQueue);
		CryptoPP::SecByteBlock priv(privQueue.CurrentSize());
		privQueue.Get(priv.data(), priv.size());
		Password privPwd = Implementation::KeyPair::PasswordFromSecBlock(priv);

		return std::make_shared<ED25519>(
			std::move(pubStr),
			std::move(privPwd)
		);
	} catch (...) {
		return nullptr;
	}
}
