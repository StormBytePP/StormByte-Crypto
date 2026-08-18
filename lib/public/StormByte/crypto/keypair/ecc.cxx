#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

ECC::PointerType ECC::Generate(unsigned short bits) noexcept {
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

		CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decryptor(RNG(), curve);
		CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encryptor(decryptor);

		return std::make_shared<ECC>(
			Implementation::KeyPair::SerializeKey(encryptor.GetPublicKey()),
			Implementation::KeyPair::SerializeKeyBinary(decryptor.GetPrivateKey())
		);
	} catch (...) {
		return nullptr;
	}
}
