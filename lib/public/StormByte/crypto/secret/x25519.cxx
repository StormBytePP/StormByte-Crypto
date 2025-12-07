#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/crypto/secret/implementation.hxx>

#include <xed25519.h>

using namespace StormByte::Crypto::Secret;

std::optional<std::string> X25519::DoShare(const std::string& peerPublicKey) const noexcept {
	if (!m_keypair || !m_keypair->PrivateKey().has_value()) {
		return std::nullopt;
	}
	try {
		// Use base64-encoded raw SecByteBlock keys and derive the shared
		// secret via the x25519 agreement implementation.
		return AgreementDeriveSharedSecret<CryptoPP::x25519>(m_keypair->PrivateKey().value(), peerPublicKey);
	} catch (...) {
		return std::nullopt;
	}
}
