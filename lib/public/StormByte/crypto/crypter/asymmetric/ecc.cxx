#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/crypto/crypter/asymmetric/implementation.hxx>

#include <eccrypto.h>

using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;

using namespace StormByte::Crypto::Crypter;

bool ECC::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return EncryptAsymmetric<ECIES::Encryptor, ECIES::PublicKey>(input, m_keypair, output);
}

StormByte::Buffer::Consumer ECC::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return EncryptAsymmetric<ECIES::Encryptor, ECIES::PublicKey>(consumer, m_keypair, mode);
}

bool ECC::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return DecryptAsymmetric<ECIES::Decryptor, ECIES::PrivateKey>(input, m_keypair, output);
}

StormByte::Buffer::Consumer ECC::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return DecryptAsymmetric<ECIES::Decryptor, ECIES::PrivateKey>(consumer, m_keypair, mode);
}
