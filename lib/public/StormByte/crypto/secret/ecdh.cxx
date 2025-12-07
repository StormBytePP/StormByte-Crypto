#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/implementation.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::Secret;

std::optional<std::string> ECDH::DoShare(const std::string& peerPublicKey) const noexcept {
	if (!m_keypair || !m_keypair->PrivateKey().has_value()) {
		return std::nullopt;
	}
	try {
		// Use base64 key strings directly with the helper which decodes them
		// Select the curve
		// <todo> Make curve selection dynamic based on key parameters or the KeyPair used
		CryptoPP::OID curve = CryptoPP::ASN1::secp256r1();

		// Initialize ECDH domain params and derive shared secret using helper
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams(curve);
		return AgreementDeriveSharedSecret<CryptoPP::ECDH<CryptoPP::ECP>::Domain>(m_keypair->PrivateKey().value(), peerPublicKey, ecParams);
	} catch (...) {
		return std::nullopt;
	}
}