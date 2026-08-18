#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <rsa.h>

using namespace StormByte::Crypto::KeyPair;

RSA::PointerType RSA::Generate(unsigned short key_size) noexcept {
	if (key_size != 1024 && key_size != 2048 && key_size != 3072 && key_size != 4096)
		return nullptr;

	try {
		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(RNG(), key_size);

		CryptoPP::RSA::PublicKey publicKey;
		publicKey.AssignFrom(privateKey);

		return std::make_shared<RSA>(
			Implementation::KeyPair::SerializeKey(publicKey),
			Implementation::KeyPair::SerializeKeyBinary(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}
