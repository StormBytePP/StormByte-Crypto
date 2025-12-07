#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/x25519.hxx>

namespace StormByte::Crypto::Secret {
	Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept {
		// We need to check if keys are compatible with the secret type here
		switch (type) {
			case Type::ECDH:
				if (keypair->Type() != KeyPair::Type::ECDH) {
					return nullptr;
				}
				return std::make_shared<ECDH>(keypair);
			case Type::X25519:
				if (keypair->Type() != KeyPair::Type::X25519) {
					return nullptr;
				}
				return std::make_shared<X25519>(keypair);
			default:
				return nullptr;
		}
	}
}