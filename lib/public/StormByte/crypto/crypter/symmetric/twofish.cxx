#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
#include <StormByte/crypto/implementation/crypter/symmetric/api.hxx>

#include <twofish.h>

using namespace StormByte::Crypto::Crypter;

bool TwoFish::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Twofish::BLOCKSIZE);
}

StormByte::Buffer::Consumer TwoFish::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Twofish::BLOCKSIZE);
}

bool TwoFish::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Twofish::BLOCKSIZE);
}

StormByte::Buffer::Consumer TwoFish::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Twofish::BLOCKSIZE);
}
