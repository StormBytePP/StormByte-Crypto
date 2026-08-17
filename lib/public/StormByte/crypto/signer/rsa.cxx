#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/crypto/signer/implementation.hxx>

#include <rsa.h>

using namespace StormByte::Crypto::Signer;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;

bool RSA::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	return StormByte::Crypto::Signer::Sign<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer, CryptoPP::RSA::PrivateKey>(
		data, m_keypair, output);
}

Consumer RSA::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	return StormByte::Crypto::Signer::Sign<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer, CryptoPP::RSA::PrivateKey>(
		consumer, m_keypair, mode);
}

bool RSA::DoVerify(std::span<const std::byte> data, const std::string& signature) const noexcept {
	return StormByte::Crypto::Signer::Verify<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier, CryptoPP::RSA::PublicKey>(
		data, signature, m_keypair);
}

bool RSA::DoVerify(Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return StormByte::Crypto::Signer::Verify<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier, CryptoPP::RSA::PublicKey>(
		consumer, signature, m_keypair, mode);
}
