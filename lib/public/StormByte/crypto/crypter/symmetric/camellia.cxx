#include <StormByte/crypto/crypter/symmetric/camellia.hxx>
#include <StormByte/crypto/crypter/symmetric/implementation.hxx>

#include <camellia.h>

using namespace StormByte::Crypto::Crypter;

bool Camellia::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return EncryptCBC<CryptoPP::Camellia, CryptoPP::CBC_Mode<CryptoPP::Camellia>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Camellia::BLOCKSIZE);
}

StormByte::Buffer::Consumer Camellia::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return EncryptCBC<CryptoPP::Camellia, CryptoPP::CBC_Mode<CryptoPP::Camellia>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Camellia::BLOCKSIZE);
}

bool Camellia::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return DecryptCBC<CryptoPP::Camellia, CryptoPP::CBC_Mode<CryptoPP::Camellia>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Camellia::BLOCKSIZE);
}

StormByte::Buffer::Consumer Camellia::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return DecryptCBC<CryptoPP::Camellia, CryptoPP::CBC_Mode<CryptoPP::Camellia>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Camellia::BLOCKSIZE);
}
