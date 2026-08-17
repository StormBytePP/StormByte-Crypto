#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/secret/x25519.hxx>

#include <xed25519.h>

using namespace StormByte::Crypto::Secret;

std::optional<StormByte::Crypto::Password> X25519::Share(const std::string& peerPublicKey) const noexcept {
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return std::nullopt;

	try {
		const Password& privPwd = *m_keypair->PrivateKey();
		const unsigned char* privPtr = Helpers::PasswordAccess::Data(privPwd);
		const std::size_t privLen = Helpers::PasswordAccess::Size(privPwd);
		if (!privPtr || privLen == 0)
			return std::nullopt;

		CryptoPP::SecByteBlock priv(privPtr, privLen);
		CryptoPP::SecByteBlock pub = KeyPair::DecodeSecBlockBase64(peerPublicKey);

		CryptoPP::x25519 agreement;
		if (priv.size() != agreement.PrivateKeyLength() || pub.size() != agreement.PublicKeyLength()) {
			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);
			return std::nullopt;
		}

		CryptoPP::SecByteBlock secret(agreement.AgreedValueLength());
		const bool ok = agreement.Agree(secret, priv, pub);

		Helpers::SecureWipe(priv);
		Helpers::SecureWipe(pub);

		if (!ok)
			return std::nullopt;

		Password out(secret.data(), secret.size());
		Helpers::SecureWipe(secret);
		return out;
	} catch (...) {
		return std::nullopt;
	}
}
