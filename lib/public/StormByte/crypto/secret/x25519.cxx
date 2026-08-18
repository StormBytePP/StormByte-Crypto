#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/crypto/implementation/secret/details.hxx>

using namespace StormByte::Crypto::Secret;

std::optional<StormByte::Crypto::Password>
X25519::Share(const std::string& peerPublicKey) const noexcept
{
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return std::nullopt;
	return Implementation::Secret::X25519Share(
		*m_keypair->PrivateKey(), peerPublicKey);
}

std::optional<StormByte::Crypto::Password>
X25519::DeriveSharedSecret(KeyPair::Generic::PointerType keypair,
						const std::string& peerPublicKey) noexcept
{
	if (!keypair || !keypair->HasPrivateKey())
		return std::nullopt;
	return Implementation::Secret::X25519Share(
		*keypair->PrivateKey(), peerPublicKey);
}
