#include <StormByte/crypto/asymetric.hxx>
#include <StormByte/crypto/implementation/encryption/ecc.hxx>
#include <StormByte/crypto/implementation/encryption/rsa.hxx>

using namespace StormByte::Crypto;

Asymmetric::Asymmetric(const Algorithm::Asymmetric& algorithm, const class KeyPair& key_pair) noexcept
:Crypter(), m_algorithm(algorithm), m_keys(key_pair) {}

Asymmetric::Asymmetric(const Algorithm::Asymmetric& algorithm, class KeyPair&& key_pair) noexcept
:Crypter(), m_algorithm(algorithm), m_keys(std::move(key_pair)) {}

StormByte::Expected<std::string, Exception> Asymmetric::Encrypt(const std::string& input) const noexcept {
	Implementation::Encryption::ExpectedCryptoString outstr;
	switch(m_algorithm) {
		case Algorithm::Asymmetric::ECC:
			outstr = Implementation::Encryption::ECC::Encrypt(input, m_keys.PublicKey());
			break;
		case Algorithm::Asymmetric::RSA:
			outstr = Implementation::Encryption::RSA::Encrypt(input, m_keys.PublicKey());
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for encryption.");
	}

	if (outstr.has_value()) {
		return outstr.value();
	} else {
		return StormByte::Unexpected<Exception>(outstr.error());
	}
}

StormByte::Expected<StormByte::Buffer::FIFO, StormByte::Crypto::Exception> Asymmetric::Encrypt(const Buffer::FIFO& buffer) const noexcept {
	Implementation::Encryption::ExpectedCryptoBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Asymmetric::ECC:
			outbuff = Implementation::Encryption::ECC::Encrypt(buffer, m_keys.PublicKey());
			break;
		case Algorithm::Asymmetric::RSA:
			outbuff = Implementation::Encryption::RSA::Encrypt(buffer, m_keys.PublicKey());
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for encryption.");
	}

	if (outbuff.has_value()) {
		return outbuff.value();
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffer::Consumer Asymmetric::Encrypt(const Buffer::Consumer consumer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Asymmetric::ECC:
			return Implementation::Encryption::ECC::Encrypt(consumer, m_keys.PublicKey());
		case Algorithm::Asymmetric::RSA:
			return Implementation::Encryption::RSA::Encrypt(consumer, m_keys.PublicKey());
		default:
			return consumer;
	}
}

StormByte::Expected<std::string, Exception> Asymmetric::Decrypt(const std::string& input) const noexcept {
	if (!m_keys.PrivateKey().has_value()) {
		return StormByte::Unexpected<Exception>("Private key is not available for decryption.");
	}
	Implementation::Encryption::ExpectedCryptoString outstr;
	switch(m_algorithm) {
		case Algorithm::Asymmetric::ECC:
			outstr = Implementation::Encryption::ECC::Decrypt(input, m_keys.PrivateKey().value());
			break;
		case Algorithm::Asymmetric::RSA:
			outstr = Implementation::Encryption::RSA::Decrypt(input, m_keys.PrivateKey().value());
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for decryption.");
	}

	if (outstr.has_value()) {
		return outstr.value();
	} else {
		return StormByte::Unexpected<Exception>(outstr.error());
	}
}

StormByte::Expected<StormByte::Buffer::FIFO, StormByte::Crypto::Exception> Asymmetric::Decrypt(const Buffer::FIFO& buffer) const noexcept {
	if (!m_keys.PrivateKey().has_value()) {
		return StormByte::Unexpected<Exception>("Private key is not available for decryption.");
	}
	Implementation::Encryption::ExpectedCryptoBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Asymmetric::ECC:
			outbuff = Implementation::Encryption::ECC::Decrypt(buffer, m_keys.PrivateKey().value());
			break;
		case Algorithm::Asymmetric::RSA:
			outbuff = Implementation::Encryption::RSA::Decrypt(buffer, m_keys.PrivateKey().value());
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for decryption.");
	}

	if (outbuff.has_value()) {
		return outbuff.value();
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffer::Consumer Asymmetric::Decrypt(const Buffer::Consumer consumer) const noexcept {
	if (!m_keys.PrivateKey().has_value()) {
		auto producer = std::make_shared<Buffer::Producer>();
		producer->Close();
		return producer->Consumer();
	}
	switch(m_algorithm) {
		case Algorithm::Asymmetric::ECC:
			return Implementation::Encryption::ECC::Decrypt(consumer, m_keys.PrivateKey().value());
		case Algorithm::Asymmetric::RSA:
			return Implementation::Encryption::RSA::Decrypt(consumer, m_keys.PrivateKey().value());
		default:
			return consumer;
	}
}

const KeyPair& Asymmetric::KeyPair() const noexcept {
	return m_keys;
}