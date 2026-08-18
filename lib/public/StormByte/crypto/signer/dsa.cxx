#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/crypto/implementation/signer/api.hxx>

#include <dsa.h>

using namespace StormByte::Crypto::Signer;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;

bool DSA::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	return Implementation::Signer::Sign<CryptoPP::DSA::Signer, CryptoPP::DSA::PrivateKey>(
		data, m_keypair, output);
}

Consumer DSA::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Signer::Sign<CryptoPP::DSA::Signer, CryptoPP::DSA::PrivateKey>(
		consumer, m_keypair, mode);
}

bool DSA::DoVerify(std::span<const std::byte> data, const std::string& signature) const noexcept {
	return Implementation::Signer::Verify<CryptoPP::DSA::Verifier, CryptoPP::DSA::PublicKey>(
		data, signature, m_keypair);
}

bool DSA::DoVerify(Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return Implementation::Signer::Verify<CryptoPP::DSA::Verifier, CryptoPP::DSA::PublicKey>(
		consumer, signature, m_keypair, mode);
}
