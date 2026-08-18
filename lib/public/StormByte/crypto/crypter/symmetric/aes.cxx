#include <StormByte/crypto/crypter/symmetric/aes.hxx>
#include <StormByte/crypto/implementation/crypter/symmetric/api.hxx>

#include <aes.h>

using namespace StormByte::Crypto::Crypter;

bool AES::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptCBC<CryptoPP::AES, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::AES::BLOCKSIZE);
}

StormByte::Buffer::Consumer AES::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptCBC<CryptoPP::AES, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::AES::BLOCKSIZE);
}

bool AES::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptCBC<CryptoPP::AES, CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::AES::BLOCKSIZE);
}

StormByte::Buffer::Consumer AES::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptCBC<CryptoPP::AES, CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::AES::BLOCKSIZE);
}
