#include <StormByte/crypto/asymetric.hxx>
#include <StormByte/crypto/implementation/encryption/ecc.hxx>
#include <StormByte/crypto/implementation/encryption/rsa.hxx>

using namespace StormByte::Crypto;

Asymmetric::Asymmetric(const Algorithm::Asymmetric& algorithm, const class KeyPair& key_pair) noexcept
:Crypter(), m_algorithm(algorithm), m_keys(key_pair) {}

Asymmetric::Asymmetric(const Algorithm::Asymmetric& algorithm, class KeyPair&& key_pair) noexcept
:Crypter(), m_algorithm(algorithm), m_keys(std::move(key_pair)) {}

StormByte::Expected<std::string, Exception> Asymmetric::Encrypt(const std::string& input) const noexcept {
	Implementation::Encryption::ExpectedCryptoFutureString outstr;
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

StormByte::Expected<StormByte::Buffers::Simple, StormByte::Crypto::Exception> Asymmetric::Encrypt(const Buffers::Simple& buffer) const noexcept {
	Implementation::Encryption::ExpectedCryptoFutureBuffer outbuff;
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
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the encrypted data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffers::Consumer Asymmetric::Encrypt(const Buffers::Consumer consumer) const noexcept {
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
	Implementation::Encryption::ExpectedCryptoFutureString outstr;
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

StormByte::Expected<StormByte::Buffers::Simple, StormByte::Crypto::Exception> Asymmetric::Decrypt(const Buffers::Simple& buffer) const noexcept {
	Implementation::Encryption::ExpectedCryptoFutureBuffer outbuff;
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
		auto value = outbuff.value().get();
		const auto span = value.Span();

		// Serialize the decrypted data into a string
		std::string result(reinterpret_cast<const char*>(span.data()), span.size());

		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffers::Consumer Asymmetric::Decrypt(const Buffers::Consumer consumer) const noexcept {
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