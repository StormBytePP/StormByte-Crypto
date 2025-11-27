#include <StormByte/crypto/signer.hxx>
#include <StormByte/crypto/implementation/encryption/dsa.hxx>
#include <StormByte/crypto/implementation/encryption/ecdsa.hxx>
#include <StormByte/crypto/implementation/encryption/rsa.hxx>

using namespace StormByte::Crypto;

Signer::Signer(const Algorithm::Sign& algorithm, const KeyPair& keypair) noexcept
:m_algorithm(algorithm), m_keys(keypair) {}

Signer::Signer(const Algorithm::Sign& algorithm, KeyPair&& keypair) noexcept
:m_algorithm(algorithm), m_keys(std::move(keypair)) {}

StormByte::Expected<std::string, Exception> Signer::Sign(const std::string& input) const noexcept {
	if (!m_keys.PrivateKey().has_value()) {
		return StormByte::Unexpected<Exception>("Private key is not available for signing.");
	}
	Implementation::Encryption::ExpectedCryptoString outstr;
	switch(m_algorithm) {
		case Algorithm::Sign::DSA:
			outstr = Implementation::Encryption::DSA::Sign(input, m_keys.PrivateKey().value());
			break;
		case Algorithm::Sign::ECDSA:
			outstr = Implementation::Encryption::ECDSA::Sign(input, m_keys.PrivateKey().value());
			break;
		case Algorithm::Sign::RSA:
			outstr = Implementation::Encryption::RSA::Sign(input, m_keys.PrivateKey().value());
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for signing.");
	}

	if (outstr.has_value()) {
		return outstr.value();
	} else {
		return StormByte::Unexpected<Exception>(outstr.error());
	}
}

StormByte::Expected<std::string, Exception> Signer::Sign(const Buffer::FIFO& buffer) const noexcept {
	if (!m_keys.PrivateKey().has_value()) {
		return StormByte::Unexpected<Exception>("Private key is not available for signing.");
	}
	Implementation::Encryption::ExpectedCryptoBuffer outbuff;
	switch(m_algorithm) {
		case Algorithm::Sign::DSA:
			outbuff = Implementation::Encryption::DSA::Sign(buffer, m_keys.PrivateKey().value());
			break;
		case Algorithm::Sign::ECDSA:
			outbuff = Implementation::Encryption::ECDSA::Sign(buffer, m_keys.PrivateKey().value());
			break;
		case Algorithm::Sign::RSA:
			outbuff = Implementation::Encryption::RSA::Sign(buffer, m_keys.PrivateKey().value());
			break;
		default:
			return StormByte::Unexpected<Exception>("Invalid algorithm for signing.");
	}

	if (outbuff.has_value()) {
		auto data = outbuff.value().Extract(0);
		if (!data.has_value()) {
			return StormByte::Unexpected<Exception>("Failed to extract data from buffer");
		}
		std::string result(reinterpret_cast<const char*>(data.value().data()), data.value().size());
		return result;
	} else {
		return StormByte::Unexpected<Exception>(outbuff.error());
	}
}

StormByte::Buffer::Consumer Signer::Sign(const Buffer::Consumer consumer) const noexcept {
	if (!m_keys.PrivateKey().has_value()) {
		auto producer = std::make_shared<Buffer::Producer>();
		producer->Close();
		return producer->Consumer();
	}
	switch(m_algorithm) {
		case Algorithm::Sign::DSA:
			return Implementation::Encryption::DSA::Sign(consumer, m_keys.PrivateKey().value());
		case Algorithm::Sign::ECDSA:
			return Implementation::Encryption::ECDSA::Sign(consumer, m_keys.PrivateKey().value());
		case Algorithm::Sign::RSA:
			return Implementation::Encryption::RSA::Sign(consumer, m_keys.PrivateKey().value());
		default:
			return consumer;
	}
}

bool Signer::Verify(const std::string& message, const std::string& signature) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Sign::DSA:
			return Implementation::Encryption::DSA::Verify(message, signature, m_keys.PublicKey());
		case Algorithm::Sign::ECDSA:
			return Implementation::Encryption::ECDSA::Verify(message, signature, m_keys.PublicKey());
		case Algorithm::Sign::RSA:
			return Implementation::Encryption::RSA::Verify(message, signature, m_keys.PublicKey());
		default:
			return false;
	}
}

bool Signer::Verify(const Buffer::FIFO& buffer, const std::string& signature) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Sign::DSA:
			return Implementation::Encryption::DSA::Verify(buffer, signature, m_keys.PublicKey());
		case Algorithm::Sign::ECDSA:
			return Implementation::Encryption::ECDSA::Verify(buffer, signature, m_keys.PublicKey());
		case Algorithm::Sign::RSA:
			return Implementation::Encryption::RSA::Verify(buffer, signature, m_keys.PublicKey());
		default:
			return false;
	}
}

bool Signer::Verify(const Buffer::Consumer consumer, const std::string& signature) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Sign::DSA:
			return Implementation::Encryption::DSA::Verify(consumer, signature, m_keys.PublicKey());
		case Algorithm::Sign::ECDSA:
			return Implementation::Encryption::ECDSA::Verify(consumer, signature, m_keys.PublicKey());
		case Algorithm::Sign::RSA:
			return Implementation::Encryption::RSA::Verify(consumer, signature, m_keys.PublicKey());
		default:
			return false;
	}
}