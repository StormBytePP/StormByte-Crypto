#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>

namespace StormByte::Crypto::Crypter {
	Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept {
		/* We need to do sanity checks here to check if keys match */
		switch (type) {
			case Type::ECC:
				if (keypair->Type() != KeyPair::Type::ECC)
					return nullptr;
				return std::make_shared<ECC>(keypair);
			case Type::RSA:
				if (keypair->Type() != KeyPair::Type::RSA)
					return nullptr;
				return std::make_shared<RSA>(keypair);
			default:
				return nullptr;
		}
	}

	Generic::PointerType Create(enum Type type, const KeyPair::Generic& keypair) noexcept {
		return Create(type, keypair.Clone());
	}

	Generic::PointerType Create(enum Type type, KeyPair::Generic&& keypair) noexcept {
		return Create(type, keypair.Move());
	}
}


