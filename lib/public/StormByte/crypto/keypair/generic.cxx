#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>

using namespace StormByte::Crypto::KeyPair;

// Save/Load disabled until rewritten for binary private keys (Password).
bool Generic::Save(const std::filesystem::path& /*path*/, const std::string& /*name*/) const noexcept {
	return false;
}

Generic::PointerType Create(Type type, unsigned short bits) noexcept {
	switch (type) {
		case Type::DSA:
			return DSA::Generate(bits);
		case Type::ECC:
			return ECC::Generate(bits);
		case Type::ECDH:
			return ECDH::Generate(bits);
		case Type::ECDSA:
			return ECDSA::Generate(bits);
		case Type::ED25519:
			return ED25519::Generate(bits);
		case Type::RSA:
			return RSA::Generate(bits);
		case Type::X25519:
			return X25519::Generate(bits);
		default:
			return nullptr;
	}
}

Generic::PointerType Load(const std::filesystem::path& /*publicKeyPath*/, const std::filesystem::path& /*privateKeyPath*/) noexcept {
	return nullptr;
}
