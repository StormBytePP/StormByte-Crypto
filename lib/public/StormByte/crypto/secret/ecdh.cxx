#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/implementation.hxx>

#include <eccrypto.h>
#include <oids.h>
#include <queue.h>

using namespace StormByte::Crypto::Secret;

namespace {
	CryptoPP::OID CurveFromBits(unsigned short bits) noexcept {
		switch (bits) {
			case 256: return CryptoPP::ASN1::secp256r1();
			case 384: return CryptoPP::ASN1::secp384r1();
			case 521: return CryptoPP::ASN1::secp521r1();
			default:  return CryptoPP::OID();
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
		if (!privPtr || privLen == 0)
			return std::nullopt;

		CryptoPP::SecByteBlock priv(privPtr, privLen);
		CryptoPP::SecByteBlock pub = KeyPair::DecodeSecBlockBase64(peerPublicKey);

		// Fast path: raw scalar + uncompressed point (same sizes as Domain)
		if (priv.size() == domain.PrivateKeyLength() && pub.size() == domain.PublicKeyLength()) {
			CryptoPP::SecByteBlock secret(domain.AgreedValueLength());
			const bool ok = domain.Agree(secret, priv, pub);
			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);
			if (!ok) {
				Helpers::SecureWipe(secret);
				return std::nullopt;
			}
			Password out(secret.data(), secret.size());
			Helpers::SecureWipe(secret);
			return out;
		}

		// ASN.1 / SerializeKey path (OpenSSL Load + library Generate)
		CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
		{
			CryptoPP::ArraySource src(privPtr, privLen, true);
			privKey.Load(src);
			if (!privKey.Validate(RNG(), 2)) {
				Helpers::SecureWipe(priv);
				Helpers::SecureWipe(pub);
				return std::nullopt;
			}
		}

		CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
		{
			CryptoPP::SecByteBlock pubDer = pub;
			if (pubDer.empty()) {
				Helpers::SecureWipe(priv);
				return std::nullopt;
			}
			CryptoPP::ArraySource src(pubDer.data(), pubDer.size(), true);
			pubKey.Load(src);
			if (!pubKey.Validate(RNG(), 2)) {
				Helpers::SecureWipe(priv);
				Helpers::SecureWipe(pub);
				Helpers::SecureWipe(pubDer);
				return std::nullopt;
			}
			Helpers::SecureWipe(pubDer);
		}

		const size_t privLenRaw = domain.PrivateKeyLength();
		const size_t pubLenRaw = domain.PublicKeyLength();
		CryptoPP::SecByteBlock privRaw(privLenRaw);
		CryptoPP::SecByteBlock pubRaw(pubLenRaw);

		CryptoPP::Integer d = privKey.GetPrivateExponent();
		d.Encode(privRaw.data(), privLenRaw);

		CryptoPP::ECP::Point Q = pubKey.GetPublicElement();
		const size_t coordLen = (pubLenRaw - 1) / 2;
		pubRaw[0] = 0x04;
		Q.x.Encode(pubRaw.data() + 1, coordLen);
		Q.y.Encode(pubRaw.data() + 1 + coordLen, coordLen);

		Helpers::SecureWipe(priv);
		Helpers::SecureWipe(pub);

		CryptoPP::SecByteBlock secret(domain.AgreedValueLength());
		bool ok = domain.Agree(secret, privRaw, pubRaw);
		if (!ok) {
			ok = domain.Agree(secret, pubRaw, privRaw);
		}

		Helpers::SecureWipe(privRaw);
		Helpers::SecureWipe(pubRaw);

		if (!ok) {
			Helpers::SecureWipe(secret);
			return std::nullopt;
		}

		Password out(secret.data(), secret.size());
		Helpers::SecureWipe(secret);
		return out;
	} catch (...) {
		return std::nullopt;
	}
}
