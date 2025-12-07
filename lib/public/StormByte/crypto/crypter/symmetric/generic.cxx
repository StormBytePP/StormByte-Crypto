#include <StormByte/crypto/crypter/symmetric/aes.hxx>
#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/crypter/symmetric/camellia.hxx>
#include <StormByte/crypto/crypter/symmetric/chachapoly.hxx>
#include <StormByte/crypto/crypter/symmetric/serpent.hxx>
#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
#include <StormByte/crypto/random.hxx>

#include <hex.h>

using namespace StormByte::Crypto::Crypter;

std::string StormByte::Crypto::Crypter::Symmetric::RandomPassword(std::size_t length) noexcept {
	CryptoPP::SecByteBlock password(length);
	RNG().GenerateBlock(password, length);

	std::string passwordString;
	CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(passwordString));
	encoder.Put(password.data(), password.size());
	encoder.MessageEnd();

	return passwordString;
}

namespace StormByte::Crypto::Crypter {
	Generic::PointerType Create(enum Type type, const std::string& password) noexcept {
		switch (type) {
			case Type::AES:
				return std::make_shared<AES>(password);
			case Type::AES_GCM:
				return std::make_shared<AES_GCM>(password);
			case Type::ChaChaPoly:
				return std::make_shared<ChaChaPoly>(password);
			case Type::Camellia:
				return std::make_shared<Camellia>(password);
			case Type::Serpent:
				return std::make_shared<Serpent>(password);
			case Type::TwoFish:
				return std::make_shared<TwoFish>(password);
			default:
				return nullptr;
		}
	}
}