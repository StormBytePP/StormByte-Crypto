#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/implementation/secret/details.hxx>

using namespace StormByte::Crypto::Secret;

std::optional<StormByte::Crypto::Password>
ECDH::Share(const std::string& peerPublicKey) const noexcept
{
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return std::nullopt;
	return Implementation::Secret::ECDHShare(
		*m_keypair->PrivateKey(), peerPublicKey, m_bits);
}
