#include <StormByte/crypto/crypter/symmetric/aes.hxx>
#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/crypter/symmetric/camellia.hxx>
#include <StormByte/crypto/crypter/symmetric/chachapoly.hxx>
#include <StormByte/crypto/crypter/symmetric/generic.hxx>
#include <StormByte/crypto/crypter/symmetric/serpent.hxx>
#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>

using namespace StormByte::Crypto::Crypter;

Symmetric::~Symmetric() noexcept = default;

StormByte::Crypto::Password Symmetric::RandomPassword(std::size_t length) noexcept {
	CryptoPP::SecByteBlock raw(length);
	RNG().GenerateBlock(raw, length);

	class Password result(raw.data(), raw.size());
	Helpers::SecureWipe(raw);
	return result;
}

Generic::PointerType Create(enum Type type, StormByte::Crypto::Password password) noexcept {
	switch (type) {
		case Type::AES:
			return std::make_shared<AES>(std::move(password));
		case Type::AES_GCM:
			return std::make_shared<AES_GCM>(std::move(password));
		case Type::ChaChaPoly:
			return std::make_shared<ChaChaPoly>(std::move(password));
		case Type::Camellia:
			return std::make_shared<Camellia>(std::move(password));
		case Type::Serpent:
			return std::make_shared<Serpent>(std::move(password));
		case Type::TwoFish:
			return std::make_shared<TwoFish>(std::move(password));
		default:
			return nullptr;
	}
}
