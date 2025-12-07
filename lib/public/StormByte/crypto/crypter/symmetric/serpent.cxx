#include <StormByte/crypto/crypter/symmetric/serpent.hxx>
#include <StormByte/crypto/crypter/symmetric/implementation.hxx>

#include <serpent.h>

using namespace StormByte::Crypto::Crypter;

bool Serpent::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return EncryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Serpent::BLOCKSIZE);
}

StormByte::Buffer::Consumer Serpent::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return EncryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Serpent::BLOCKSIZE);
}

bool Serpent::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return DecryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Serpent::BLOCKSIZE);
}

StormByte::Buffer::Consumer Serpent::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return DecryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Serpent::BLOCKSIZE);
}
