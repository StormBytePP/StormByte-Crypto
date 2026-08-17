#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/crypto/crypter/asymmetric/implementation.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>

#include <rsa.h>
#include <eccrypto.h>

using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;

namespace StormByte::Crypto::Crypter {

	Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept {
		/* We need to do sanity checks here to check if keys match */
		switch (type) {
			case Type::ECC:
				if (keypair->Type() != KeyPair::Type::ECC)
					return nullptr;
				return std::make_shared<ECC>(keypair);
			case Type::RSA:
				if (keypair->Type() != KeyPair::Type::RSA)
					return nullptr;
				return std::make_shared<RSA>(keypair);
			default:
				return nullptr;
		}
	}

	Generic::PointerType Create(enum Type type, const KeyPair::Generic& keypair) noexcept {
		return Create(type, keypair.Clone());
	}

	Generic::PointerType Create(enum Type type, KeyPair::Generic&& keypair) noexcept {
		return Create(type, keypair.Move());
	}

	// -------------------------------------------------------------------------
	// Encrypt overloads with Strategy
	// -------------------------------------------------------------------------

	bool Asymmetric::Encrypt(std::span<const std::byte> input, Buffer::WriteOnly& output, Strategy strategy) const noexcept {
		if (strategy == Strategy::Native) {
			return DoEncrypt(input, output);
		}

		// Hybrid
		if (Type() == Type::RSA) {
			return EncryptAsymmetricBlockEnvelope<CryptoPP::RSAES_OAEP_SHA_Encryptor, CryptoPP::RSA::PublicKey>(input, m_keypair, output);
		}
		if (Type() == Type::ECC) {
			return EncryptAsymmetricBlockEnvelope<ECIES::Encryptor, ECIES::PublicKey>(input, m_keypair, output);
		}
		return false;
	}

	bool Asymmetric::Encrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output, Strategy strategy) const noexcept {
		Buffer::DataType data;
		if (!const_cast<Buffer::ReadOnly&>(input).Read(data)) return false;
		return Encrypt(std::span<const std::byte>(data.data(), data.size()), output, strategy);
	}

	bool Asymmetric::Encrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, Strategy strategy) const noexcept {
		Buffer::DataType data;
		if (!input.Extract(data)) return false;
		return Encrypt(std::span<const std::byte>(data.data(), data.size()), output, strategy);
	}

	Buffer::Consumer Asymmetric::Encrypt(Buffer::Consumer consumer, Strategy strategy, ReadMode mode) const noexcept {
		if (strategy == Strategy::Native) {
			return DoEncrypt(consumer, mode);
		}

		// Hybrid streaming
		if (Type() == Type::RSA) {
			return EncryptAsymmetricBlockEnvelope<CryptoPP::RSAES_OAEP_SHA_Encryptor, CryptoPP::RSA::PublicKey>(consumer, m_keypair, mode);
		}
		if (Type() == Type::ECC) {
			return EncryptAsymmetricBlockEnvelope<ECIES::Encryptor, ECIES::PublicKey>(consumer, m_keypair, mode);
		}

		Producer producer;
		producer.SetError();
		return producer.Consumer();
	}

	// -------------------------------------------------------------------------
	// Decrypt overloads (auto-detect Native vs Hybrid)
	// -------------------------------------------------------------------------

	bool Asymmetric::Decrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
		// Try Hybrid first
		bool hybridOk = false;
		if (Type() == Type::RSA) {
			hybridOk = DecryptAsymmetricBlockEnvelope<CryptoPP::RSAES_OAEP_SHA_Decryptor, CryptoPP::RSA::PrivateKey>(input, m_keypair, output);
		} else if (Type() == Type::ECC) {
			hybridOk = DecryptAsymmetricBlockEnvelope<ECIES::Decryptor, ECIES::PrivateKey>(input, m_keypair, output);
		}

		if (hybridOk) return true;

		// Fallback to Native
		return DoDecrypt(input, output);
	}

	bool Asymmetric::Decrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
		Buffer::DataType data;
		if (!const_cast<Buffer::ReadOnly&>(input).Read(data)) return false;
		return Decrypt(std::span<const std::byte>(data.data(), data.size()), output);
	}

	bool Asymmetric::Decrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
		Buffer::DataType data;
		if (!input.Extract(data)) return false;
		return Decrypt(std::span<const std::byte>(data.data(), data.size()), output);
	}

	Buffer::Consumer Asymmetric::Decrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
		// Auto-detect using Peek (does not advance the read position)
		DataType headerPeek;
		if (!consumer.Peek(4, headerPeek) || headerPeek.size() < 4) {
			// Not enough data → try Native
			return DoDecrypt(consumer, mode);
		}

		uint32_t possibleEskLen = (static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[0])) << 24) |
								(static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[1])) << 16) |
								(static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[2])) << 8)  |
								(static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[3])));

		// Heuristic: reasonable ESK length for RSA/ECC is typically 32–512 bytes
		const bool looksLikeHybrid = (possibleEskLen >= 32 && possibleEskLen <= 512);

		if (looksLikeHybrid) {
			if (Type() == Type::RSA) {
				return DecryptAsymmetricBlockEnvelope<CryptoPP::RSAES_OAEP_SHA_Decryptor, CryptoPP::RSA::PrivateKey>(consumer, m_keypair, mode);
			}
			if (Type() == Type::ECC) {
				return DecryptAsymmetricBlockEnvelope<ECIES::Decryptor, ECIES::PrivateKey>(consumer, m_keypair, mode);
			}
		}

		// Fallback to Native
		return DoDecrypt(consumer, mode);
	}

}
