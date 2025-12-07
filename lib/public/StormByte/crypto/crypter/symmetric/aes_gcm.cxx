#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/crypter/symmetric/implementation.hxx>

#include <aes.h>

using namespace StormByte::Crypto::Crypter;

bool AES_GCM::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return EncryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, 12);
}

StormByte::Buffer::Consumer AES_GCM::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return EncryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12);
}

bool AES_GCM::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return DecryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, 12);
}

StormByte::Buffer::Consumer AES_GCM::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return DecryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12);
}
