#include <StormByte/crypto/crypter/symmetric/chachapoly.hxx>
#include <StormByte/crypto/crypter/symmetric/implementation.hxx>

#include <chachapoly.h>

using namespace StormByte::Crypto::Crypter;

bool ChaChaPoly::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return EncryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, 12, 32);
}

StormByte::Buffer::Consumer ChaChaPoly::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return EncryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12, 32);
}

bool ChaChaPoly::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return DecryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, 12, 32);
}

StormByte::Buffer::Consumer ChaChaPoly::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return DecryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12, 32);
}
