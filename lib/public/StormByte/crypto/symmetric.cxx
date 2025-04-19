#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/crypto/implementation/encryption/aes.hxx>
#include <StormByte/crypto/implementation/encryption/camellia.hxx>

using namespace StormByte::Crypto;

Symmetric::Symmetric(const Algorithm::Symmetric& algorithm, const size_t& password_size) noexcept
:Crypter(), m_algorithm(algorithm) {
	switch(algorithm) {
		case Algorithm::Symmetric::AES:
			m_password = Implementation::Encryption::AES::RandomPassword(password_size).value();
			break;
		case Algorithm::Symmetric::Camellia:
			m_password = Implementation::Encryption::Camellia::RandomPassword(password_size).value();
			break;
		default:
			m_password = std::string();
			break;
	}
}

Symmetric::Symmetric(const Algorithm::Symmetric& algorithm, const std::string& password) noexcept
:Crypter(), m_algorithm(algorithm), m_password(password) {}

StormByte::Expected<std::string, Exception> Symmetric::Encrypt(const std::string& input) const noexcept {
	Implementation::Encryption::ExpectedCryptoFutureBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			outbuff = Implementation::Encryption::AES::Encrypt(input, m_password);
			break;
		case Algorithm::Symmetric::Camellia:
			outbuff = Implementation::Encryption::Camellia::Encrypt(input, m_password);
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for encryption.");
	}

	if (outbuff.has_value()) {
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the encrypted data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Expected<StormByte::Buffers::Simple, StormByte::Crypto::Exception> Symmetric::Encrypt(const Buffers::Simple& buffer) const noexcept {
	Implementation::Encryption::ExpectedCryptoFutureBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			outbuff = Implementation::Encryption::AES::Encrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Camellia:
			outbuff = Implementation::Encryption::Camellia::Encrypt(buffer, m_password);
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for encryption.");
	}

	if (outbuff.has_value()) {
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the encrypted data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffers::Consumer Symmetric::Encrypt(const Buffers::Consumer consumer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			return Implementation::Encryption::AES::Encrypt(consumer, m_password);
		case Algorithm::Symmetric::Camellia:
			return Implementation::Encryption::Camellia::Encrypt(consumer, m_password);
		default:
			return consumer;
	}
}

StormByte::Expected<std::string, Exception> Symmetric::Decrypt(const std::string& input) const noexcept {
	Implementation::Encryption::ExpectedCryptoFutureBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			outbuff = Implementation::Encryption::AES::Decrypt(input, m_password);
			break;
		case Algorithm::Symmetric::Camellia:
			outbuff = Implementation::Encryption::Camellia::Decrypt(input, m_password);
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for decryption.");
	}

	if (outbuff.has_value()) {
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the decrypted data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Expected<StormByte::Buffers::Simple, StormByte::Crypto::Exception> Symmetric::Decrypt(const Buffers::Simple& buffer) const noexcept {
	Implementation::Encryption::ExpectedCryptoFutureBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			outbuff = Implementation::Encryption::AES::Decrypt(buffer, m_password);
			break;
		case Algorithm::Symmetric::Camellia:
			outbuff = Implementation::Encryption::Camellia::Decrypt(buffer, m_password);
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for decryption.");
	}

	if (outbuff.has_value()) {
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the decrypted data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffers::Consumer Symmetric::Decrypt(const Buffers::Consumer consumer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Symmetric::AES:
			return Implementation::Encryption::AES::Decrypt(consumer, m_password);
		case Algorithm::Symmetric::Camellia:
			return Implementation::Encryption::Camellia::Decrypt(consumer, m_password);
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