#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

ECDSA::PointerType ECDSA::Generate(unsigned short bits) noexcept {
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

		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
		privateKey.Initialize(RNG(), curve);

		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		return std::make_shared<ECDSA>(
			SerializeKey(publicKey),
			SerializeKeyBinary(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}
