#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <dsa.h>

using namespace StormByte::Crypto::KeyPair;

DSA::PointerType DSA::Generate(unsigned short bits) noexcept {
	try {
		CryptoPP::DSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(RNG(), bits);

		CryptoPP::DSA::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		return std::make_shared<DSA>(
			SerializeKey(publicKey),
			SerializeKeyBinary(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}
