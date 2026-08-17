#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/crypto/signer/implementation.hxx>

#include <eccrypto.h>

using namespace StormByte::Crypto::Signer;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;

bool ECDSA::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	return StormByte::Crypto::Signer::Sign<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>(
		data, m_keypair, output);
}

Consumer ECDSA::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	return StormByte::Crypto::Signer::Sign<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>(
		consumer, m_keypair, mode);
}

bool ECDSA::DoVerify(std::span<const std::byte> data, const std::string& signature) const noexcept {
	return StormByte::Crypto::Signer::Verify<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>(
		data, signature, m_keypair);
}

bool ECDSA::DoVerify(Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return StormByte::Crypto::Signer::Verify<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>(
		consumer, signature, m_keypair, mode);
}
