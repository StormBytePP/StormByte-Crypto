#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/implementation/crypter/asymmetric/api.hxx>

#include <rsa.h>

using namespace StormByte::Crypto::Crypter;

bool RSA::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Asymmetric::EncryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Encryptor, CryptoPP::RSA::PublicKey>(input, m_keypair, output);
}

StormByte::Buffer::Consumer RSA::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Asymmetric::EncryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Encryptor, CryptoPP::RSA::PublicKey>(consumer, m_keypair, mode);
}

bool RSA::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Asymmetric::DecryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Decryptor, CryptoPP::RSA::PrivateKey>(input, m_keypair, output);
}

StormByte::Buffer::Consumer RSA::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Asymmetric::DecryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Decryptor, CryptoPP::RSA::PrivateKey>(consumer, m_keypair, mode);
}
