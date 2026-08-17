#include <StormByte/crypto/secret/generic.hxx>
#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/x25519.hxx>

using namespace StormByte::Crypto::Secret;

Generic::PointerType Create(Type type, StormByte::Crypto::KeyPair::Generic::PointerType keypair) noexcept {
	if (!keypair)
		return nullptr;

	switch (type) {
		case Type::ECDH:
			if (keypair->Type() != StormByte::Crypto::KeyPair::Type::ECDH)
				return nullptr;
			return std::make_shared<ECDH>(keypair, 256);
		case Type::X25519:
			if (keypair->Type() != StormByte::Crypto::KeyPair::Type::X25519)
				return nullptr;
			return std::make_shared<X25519>(keypair);
		default:
			return nullptr;
	}
}
