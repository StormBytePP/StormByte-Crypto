#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/crypto/signer/implementation.hxx>

#include <dsa.h>

using namespace StormByte::Crypto::Signer;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;

bool DSA::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	return StormByte::Crypto::Signer::Sign<CryptoPP::DSA::Signer, CryptoPP::DSA::PrivateKey>(
		data, m_keypair, output);
}

Consumer DSA::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	return StormByte::Crypto::Signer::Sign<CryptoPP::DSA::Signer, CryptoPP::DSA::PrivateKey>(
		consumer, m_keypair, mode);
}

bool DSA::DoVerify(std::span<const std::byte> data, const std::string& signature) const noexcept {
	return StormByte::Crypto::Signer::Verify<CryptoPP::DSA::Verifier, CryptoPP::DSA::PublicKey>(
		data, signature, m_keypair);
}

bool DSA::DoVerify(Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return StormByte::Crypto::Signer::Verify<CryptoPP::DSA::Verifier, CryptoPP::DSA::PublicKey>(
		consumer, signature, m_keypair, mode);
}
