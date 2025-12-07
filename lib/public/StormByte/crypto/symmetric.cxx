#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/crypto/implementation/encryption/aes.hxx>
#include <StormByte/crypto/implementation/encryption/aes_gcm.hxx>
#include <StormByte/crypto/implementation/encryption/camellia.hxx>
#include <StormByte/crypto/implementation/encryption/chacha20.hxx>
#include <StormByte/crypto/implementation/encryption/serpent.hxx>
#include <StormByte/crypto/implementation/encryption/twofish.hxx>

using StormByte::Buffer::DataType;
using namespace StormByte::Crypto;

Symmetric::Symmetric(const Algorithm::Symmetric& algorithm, const size_t& password_size) noexcept
:Crypter(), m_algorithm(algorithm) {
	switch(algorithm) {
		case Algorithm::Symmetric::AES:
			m_password = Implementation::Encryption::AES::RandomPassword(password_size).value();
			break;
		case Algorithm::Symmetric::AES_GCM:
			m_password = Implementation::Encryption::AES_GCM::RandomPassword(password_size).value();
			break;
		case Algorithm::Symmetric::Camellia:
			m_password = Implementation::Encryption::Camellia::RandomPassword(password_size).value();
			break;
		case Algorithm::Symmetric::ChaCha20:
			m_password = Implementation::Encryption::ChaCha20::RandomPassword(password_size).value();
			break;
		case Algorithm::Symmetric::Serpent:
			m_password = Implementation::Encryption::Serpent::RandomPassword(password_size).value();
			break;
		case Algorithm::Symmetric::Twofish:
			m_password = Implementation::Encryption::Twofish::RandomPassword(password_size).value();
			break;
		default:
			m_password = std::string();
			break;
	}
}

Symmetric::Symmetric(const Algorithm::Symmetric& algorithm, const std::string& password) noexcept
:Crypter(), m_algorithm(algorithm), m_password(password) {}

StormByte::Expected<std::string, Exception> Symmetric::Encrypt(const std::string& input) const noexcept {
	Implementation::Encryption::ExpectedCryptoBuffer outbuff;
	switch(m_algorithm) {
	case Algorithm::Symmetric::AES:
		outbuff = Implementation::Encryption::AES::Encrypt(input, m_password);
		break;
	case Algorithm::Symmetric::AES_GCM:
		outbuff = Implementation::Encryption::AES_GCM::Encrypt(input, m_password);
		break;
	case Algorithm::Symmetric::Camellia:
		outbuff = Implementation::Encryption::Camellia::Encrypt(input, m_password);
		break;
	case Algorithm::Symmetric::ChaCha20:
		outbuff = Implementation::Encryption::ChaCha20::Encrypt(input, m_password);
		break;
	case Algorithm::Symmetric::Serpent:
		outbuff = Implementation::Encryption::Serpent::Encrypt(input, m_password);
		break;
	case Algorithm::Symmetric::Twofish:
		outbuff = Implementation::Encryption::Twofish::Encrypt(input, m_password);
		break;
	default:
		return StormByte::Unexpected<Exception>("Invalid algorithm for encryption.");
	}

	if (outbuff.has_value()) {
		DataType data;
		auto read_ok = outbuff.value().Extract(data);
		if (!read_ok.has_value()) {
			return Unexpected(CrypterException("Failed to extract data from buffer"));
		}
		std::string result(reinterpret_cast<const char*>(data.data()), data.size());
		return result;
	} else {
		return Unexpected(outbuff.error());
	}
}StormByte::Expected<StormByte::Buffer::FIFO, StormByte::Crypto::Exception> Symmetric::Encrypt(const Buffer::FIFO& buffer) const noexcept {
	Implementation::Encryption::ExpectedCryptoBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			outbuff = Implementation::Encryption::AES::Encrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::AES_GCM:
			outbuff = Implementation::Encryption::AES_GCM::Encrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Camellia:
			outbuff = Implementation::Encryption::Camellia::Encrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::ChaCha20:
			outbuff = Implementation::Encryption::ChaCha20::Encrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Serpent:
			outbuff = Implementation::Encryption::Serpent::Encrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Twofish:
			outbuff = Implementation::Encryption::Twofish::Encrypt(buffer, m_password);
			break;
		default:
			return Unexpected(CrypterException("Invalid algorithm for encryption."));
	}

	if (outbuff.has_value()) {
		return outbuff.value();
	} else {
		return Unexpected(outbuff.error());
	}
}

StormByte::Buffer::Consumer Symmetric::Encrypt(const Buffer::Consumer consumer) const noexcept {
	switch(m_algorithm) {
	case Algorithm::Symmetric::AES:
		return Implementation::Encryption::AES::Encrypt(consumer, m_password);
	case Algorithm::Symmetric::AES_GCM:
		return Implementation::Encryption::AES_GCM::Encrypt(consumer, m_password);
	case Algorithm::Symmetric::Camellia:
		return Implementation::Encryption::Camellia::Encrypt(consumer, m_password);
		case Algorithm::Symmetric::ChaCha20:
			return Implementation::Encryption::ChaCha20::Encrypt(consumer, m_password);
		case Algorithm::Symmetric::Serpent:
			return Implementation::Encryption::Serpent::Encrypt(consumer, m_password);
		case Algorithm::Symmetric::Twofish:
			return Implementation::Encryption::Twofish::Encrypt(consumer, m_password);
		default:
			return consumer;
	}
}

StormByte::Expected<std::string, Exception> Symmetric::Decrypt(const std::string& input) const noexcept {
	Implementation::Encryption::ExpectedCryptoBuffer outbuff;
	switch(m_algorithm) {
	case Algorithm::Symmetric::AES:
		outbuff = Implementation::Encryption::AES::Decrypt(input, m_password);
		break;
	case Algorithm::Symmetric::AES_GCM:
		outbuff = Implementation::Encryption::AES_GCM::Decrypt(input, m_password);
		break;
	case Algorithm::Symmetric::Camellia:
		outbuff = Implementation::Encryption::Camellia::Decrypt(input, m_password);
		break;
	case Algorithm::Symmetric::ChaCha20:
		outbuff = Implementation::Encryption::ChaCha20::Decrypt(input, m_password);
		break;
	case Algorithm::Symmetric::Serpent:
		outbuff = Implementation::Encryption::Serpent::Decrypt(input, m_password);
		break;
	case Algorithm::Symmetric::Twofish:
		outbuff = Implementation::Encryption::Twofish::Decrypt(input, m_password);
		break;
	default:
		return StormByte::Unexpected<Exception>("Invalid algorithm for decryption.");
	}

	if (outbuff.has_value()) {
		DataType data;
		auto read_ok = outbuff.value().Extract(data);
		if (!read_ok.has_value()) {
			return Unexpected(CrypterException("Failed to extract data from buffer"));
		}
		std::string result(reinterpret_cast<const char*>(data.data()), data.size());
		return result;
	} else {
		return Unexpected(outbuff.error());
	}
}StormByte::Expected<StormByte::Buffer::FIFO, StormByte::Crypto::Exception> Symmetric::Decrypt(const Buffer::FIFO& buffer) const noexcept {
	Implementation::Encryption::ExpectedCryptoBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			outbuff = Implementation::Encryption::AES::Decrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::AES_GCM:
			outbuff = Implementation::Encryption::AES_GCM::Decrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Camellia:
			outbuff = Implementation::Encryption::Camellia::Decrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::ChaCha20:
			outbuff = Implementation::Encryption::ChaCha20::Decrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Serpent:
			outbuff = Implementation::Encryption::Serpent::Decrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Twofish:
			outbuff = Implementation::Encryption::Twofish::Decrypt(buffer, m_password);
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

StormByte::Buffer::Consumer Symmetric::Decrypt(const Buffer::Consumer consumer) const noexcept {
	switch(m_algorithm) {
	case Algorithm::Symmetric::AES:
		return Implementation::Encryption::AES::Decrypt(consumer, m_password);
	case Algorithm::Symmetric::AES_GCM:
		return Implementation::Encryption::AES_GCM::Decrypt(consumer, m_password);
	case Algorithm::Symmetric::Camellia:
		return Implementation::Encryption::Camellia::Decrypt(consumer, m_password);
		case Algorithm::Symmetric::ChaCha20:
			return Implementation::Encryption::ChaCha20::Decrypt(consumer, m_password);
		case Algorithm::Symmetric::Serpent:
			return Implementation::Encryption::Serpent::Decrypt(consumer, m_password);
		case Algorithm::Symmetric::Twofish:
			return Implementation::Encryption::Twofish::Decrypt(consumer, m_password);
		default:
			return consumer;
	}
}

const std::string& Symmetric::Password() const noexcept {
	return m_password;
}

void Symmetric::Password(const std::string& password) noexcept {
	m_password = password;
}

void Symmetric::Password(std::string&& password) noexcept {
	m_password = std::move(password);
}