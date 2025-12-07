#include <StormByte/buffer/fifo.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/signer/implementation.hxx>

#include <hex.h>
#include <xed25519.h>

using StormByte::Buffer::FIFO;

using namespace StormByte::Crypto::Signer;

bool ED25519::DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	if (!m_keypair || !m_keypair->PrivateKey().has_value())
		return false;
	try {
		// The KeyPair stores ASN.1 keys Base64-encoded via SerializeKey(),
		// so use the stored string directly for deserialization.
		std::string privBase64 = m_keypair->PrivateKey().value();

		// Call the shared Sign template (writes raw signature bytes)
		FIFO tmpbuffer;
		bool res = ::Sign<CryptoPP::ed25519Signer, CryptoPP::ed25519PrivateKey>(
			input,
			privBase64,
			tmpbuffer
		);

		DataType signatureData;
		bool read_ok = tmpbuffer.Extract(signatureData);
		if (!res || !read_ok)
			return false;

		// Hex-encode the raw signature to preserve existing API
		std::string hexSignature;
		{
			CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexSignature));
			encoder.Put(reinterpret_cast<const uint8_t*>(signatureData.data()), signatureData.size());
			encoder.MessageEnd();
		}

		return output.Write(hexSignature);
	} catch (...) {
		return false;
	}
}

/**
 * @brief Implementation of the signing logic for Consumer buffers.
 * @param consumer The Consumer buffer to sign.
 * @param mode The read mode indicating copy or move.
 * @return A Consumer buffer containing the signed data.
 */
StormByte::Buffer::Consumer ED25519::DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	Producer producer;
	if (!m_keypair || !m_keypair->PrivateKey().has_value()) {
		producer.SetError();
		return producer.Consumer();
	}

	std::thread([consumer, producer, privateKey = m_keypair->PrivateKey().value(), mode]() mutable {
		try {
			// `privateKey` is already the Base64-encoded ASN.1 key produced by
			// `SerializeKey`, so we can use it directly.
			std::string privBase64 = privateKey;


			// Use the templated streaming Sign which returns a Consumer producing the raw signature
			auto outConsumer = ::Sign<CryptoPP::ed25519Signer, CryptoPP::ed25519PrivateKey>(consumer, privBase64, mode);

			// Read signature bytes from the returned Consumer and hex-encode them
			std::string sigRaw;
			constexpr size_t chunkSize = 4096;
			while (!outConsumer.EoF()) {
				size_t available = outConsumer.AvailableBytes();
				if (available == 0) {
					std::this_thread::yield();
					continue;
				}
				size_t toRead = std::min(available, chunkSize);
				DataType outData;
				auto read_ok = outConsumer.Extract(toRead, outData);
				if (!read_ok) {
					producer.SetError();
					return;
				}
				sigRaw.append(reinterpret_cast<const char*>(outData.data()), outData.size());
			}

			// Hex-encode the binary signature
			std::string hexSignature;
			{
				CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexSignature));
				encoder.Put(reinterpret_cast<const uint8_t*>(sigRaw.data()), sigRaw.size());
				encoder.MessageEnd();
			}

			if (!producer.Write(std::move(hexSignature))) {
				producer.SetError();
				return;
			}
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();
	
	return producer.Consumer();
}

bool ED25519::DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept {
	try {
		// Public key is stored as Base64-encoded ASN.1 via SerializeKey(),
		// so use it directly for verification.
		std::string pubBase64 = m_keypair->PublicKey();

		// Convert signature hex -> raw bytes
		std::string sigRaw;
		{
			CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(sigRaw));
			decoder.Put(reinterpret_cast<const uint8_t*>(signature.data()), signature.size());
			decoder.MessageEnd();
		}

		// Call Verify template (expects raw signature and Base64-encoded key)
		return ::Verify<CryptoPP::ed25519Verifier, CryptoPP::ed25519PublicKey>(
			std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()),
			sigRaw,
			pubBase64
		);
	} catch (...) {
		return false;
	}
}
	
bool ED25519::DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	try {
		// Public key stored as Base64 ASN.1; use directly.
		std::string pubBase64 = m_keypair->PublicKey();

		std::string sigRaw;
		{
			CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(sigRaw));
			decoder.Put(reinterpret_cast<const uint8_t*>(signature.data()), signature.size());
			decoder.MessageEnd();
		}

		return ::Verify<CryptoPP::ed25519Verifier, CryptoPP::ed25519PublicKey>(consumer, sigRaw, pubBase64, mode);
	} catch (...) {
		return false;
	}
}