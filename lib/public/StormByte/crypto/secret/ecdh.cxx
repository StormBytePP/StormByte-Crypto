#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/secret/ecdh.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::Secret;

namespace {
	CryptoPP::OID CurveFromBits(unsigned short bits) noexcept {
		switch (bits) {
			case 256: return CryptoPP::ASN1::secp256r1();
			case 384: return CryptoPP::ASN1::secp384r1();
			case 521: return CryptoPP::ASN1::secp521r1();
			default: return CryptoPP::OID();
		}
	}
}

std::optional<StormByte::Crypto::Password> ECDH::Share(const std::string& peerPublicKey) const noexcept {
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return std::nullopt;

	try {
		const CryptoPP::OID curve = CurveFromBits(m_bits);
		if (curve.Empty())
			return std::nullopt;

		CryptoPP::ECDH<CryptoPP::ECP>::Domain domain(curve);

		const Password& privPwd = *m_keypair->PrivateKey();
		const unsigned char* privPtr = Helpers::PasswordAccess::Data(privPwd);
		const std::size_t privLen = Helpers::PasswordAccess::Size(privPwd);
		if (!privPtr || privLen != domain.PrivateKeyLength())
			return std::nullopt;

		CryptoPP::SecByteBlock priv(privPtr, privLen);
		CryptoPP::SecByteBlock pub = KeyPair::DecodeSecBlockBase64(peerPublicKey);
		if (pub.size() != domain.PublicKeyLength()) {
			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);
			return std::nullopt;
		}

		CryptoPP::SecByteBlock secret(domain.AgreedValueLength());
		const bool ok = domain.Agree(secret, priv, pub);

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
