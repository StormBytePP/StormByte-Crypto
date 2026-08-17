#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

ECDH::PointerType ECDH::Generate(unsigned short bits) noexcept {
	try {
		CryptoPP::OID curve;
		switch (bits) {
			case 256:
				curve = CryptoPP::ASN1::secp256r1();
				break;
			case 384:
				curve = CryptoPP::ASN1::secp384r1();
				break;
			case 521:
				curve = CryptoPP::ASN1::secp521r1();
				break;
			default:
				return nullptr;
		}

		CryptoPP::ECDH<CryptoPP::ECP>::Domain domain(curve);

		CryptoPP::SecByteBlock priv(domain.PrivateKeyLength());
		CryptoPP::SecByteBlock pub(domain.PublicKeyLength());
		domain.GenerateKeyPair(RNG(), priv, pub);

		auto pubStr = EncodeSecBlockBase64(pub);
		Password privPwd = PasswordFromSecBlock(priv);
		Helpers::SecureWipe(pub);

		return std::make_shared<ECDH>(
			std::move(pubStr),
			std::move(privPwd)
		);
	} catch (...) {
		return nullptr;
	}
}
