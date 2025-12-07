#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/crypto/signer/implementation.hxx>

#include <eccrypto.h>

using CryptoECDSA = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

using namespace StormByte::Crypto::Signer;

bool ECDSA::DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return ::Sign<CryptoECDSA::Signer, CryptoECDSA::PrivateKey>(
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
StormByte::Buffer::Consumer ECDSA::DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return ::Sign<CryptoECDSA::Signer, CryptoECDSA::PrivateKey>(
		consumer,
		m_keypair,
		mode
	);
}

bool ECDSA::DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept {
	return ::Verify<CryptoECDSA::Verifier, CryptoECDSA::PublicKey>(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()), 
		signature,
		m_keypair
	);
}
	
bool ECDSA::DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return ::Verify<CryptoECDSA::Verifier, CryptoECDSA::PublicKey>(
		consumer,
		signature,
		m_keypair,
		mode
	);
}