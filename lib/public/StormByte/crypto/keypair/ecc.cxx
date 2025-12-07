#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;

ECC::PointerType ECC::Generate(unsigned short key_size) noexcept {
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
		ECIES::PrivateKey privateKey;
		privateKey.Initialize(RNG(), curve_oid);

		// Generate public key
		ECIES::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		return std::make_shared<ECC>(
			SerializeKey(publicKey),
			SerializeKey(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}