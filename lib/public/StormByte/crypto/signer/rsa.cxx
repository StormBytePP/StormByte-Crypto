#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/crypto/signer/implementation.hxx>

#include <rsa.h>

using namespace StormByte::Crypto::Signer;

bool RSA::DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return ::Sign<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer, CryptoPP::RSA::PrivateKey>(
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
StormByte::Buffer::Consumer RSA::DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return ::Sign<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer, CryptoPP::RSA::PrivateKey>(
		consumer,
		m_keypair,
		mode
	);
}

bool RSA::DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept {
	return ::Verify<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier, CryptoPP::RSA::PublicKey>(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()), 
		signature,
		m_keypair
	);
}
	
bool RSA::DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return ::Verify<CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier, CryptoPP::RSA::PublicKey>(
		consumer,
		signature,
		m_keypair,
		mode
	);
}