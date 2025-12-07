#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/crypto/signer/implementation.hxx>

#include <dsa.h>

using namespace StormByte::Crypto::Signer;

bool DSA::DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return ::Sign<CryptoPP::DSA2<CryptoPP::SHA1>::Signer, CryptoPP::DSA::PrivateKey>(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()), 
		m_keypair,
		output
	);
}

/**
 * @brief Implementation of the signing logic for Consumer buffers.
 * @param consumer The Consumer buffer to sign.
 * @param mode The read mode indicating copy or move.
 * @return A Consumer buffer containing the signed data.
 */
StormByte::Buffer::Consumer DSA::DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return ::Sign<CryptoPP::DSA2<CryptoPP::SHA1>::Signer, CryptoPP::DSA::PrivateKey>(
		consumer,
		m_keypair,
		mode
	);
}

bool DSA::DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept {
	return ::Verify<CryptoPP::DSA2<CryptoPP::SHA1>::Verifier, CryptoPP::DSA::PublicKey>(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()), 
		signature,
		m_keypair
	);
}
	
bool DSA::DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return ::Verify<CryptoPP::DSA2<CryptoPP::SHA1>::Verifier, CryptoPP::DSA::PublicKey>(
		consumer,
		signature,
		m_keypair,
		mode
	);
}