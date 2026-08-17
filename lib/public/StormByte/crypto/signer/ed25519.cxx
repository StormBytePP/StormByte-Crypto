#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/random.hxx>

#include <xed25519.h>
#include <filters.h>
#include <queue.h>

#include <memory>
#include <thread>

using namespace StormByte::Crypto::Signer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;

bool ED25519::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return false;

	try {
		const Password& priv = *m_keypair->PrivateKey();
		const unsigned char* privData = Helpers::PasswordAccess::Data(priv);
		const std::size_t privSize = Helpers::PasswordAccess::Size(priv);
		if (!privData || privSize == 0)
			return false;

		CryptoPP::ByteQueue queue;
		queue.Put(privData, privSize);

		CryptoPP::ed25519::Signer signer;
		signer.AccessPrivateKey().Load(queue);

		DataType signature(signer.SignatureLength());
		signer.SignMessage(
			RNG(),
			reinterpret_cast<const CryptoPP::byte*>(data.data()),
			data.size_bytes(),
			reinterpret_cast<CryptoPP::byte*>(signature.data())
		);

		return output.Write(std::move(signature));
	} catch (...) {
		return false;
	}
}

Consumer ED25519::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	Producer producer;
	if (!m_keypair || !m_keypair->HasPrivateKey()) {
		producer.SetError();
		return producer.Consumer();
	}

	Password privKey = *m_keypair->PrivateKey();

	std::thread([consumer, producer, privKey = std::move(privKey), mode]() mutable {
		try {
			const unsigned char* privData = Helpers::PasswordAccess::Data(privKey);
			const std::size_t privSize = Helpers::PasswordAccess::Size(privKey);
			if (!privData || privSize == 0) {
				producer.SetError();
				return;
			}

			CryptoPP::ByteQueue queue;
			queue.Put(privData, privSize);

			CryptoPP::ed25519::Signer signer;
			signer.AccessPrivateKey().Load(queue);

			DataType signature;
			auto filter = std::unique_ptr<CryptoPP::SignerFilter>(
				new CryptoPP::SignerFilter(
					RNG(),
					signer,
					new CryptoPP::StringSinkTemplate<DataType>(signature)
				)
			);

			constexpr size_t chunkSize = 4096;
			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				bool read_ok = (mode == ReadMode::Copy)
					? consumer.Read(bytesToRead, data)
					: consumer.Extract(bytesToRead, data);
				if (!read_ok) {
					producer.SetError();
					return;
				}

				filter->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
			}

			filter->MessageEnd();

			if (!producer.Write(std::move(signature))) {
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

bool ED25519::DoVerify(std::span<const std::byte> data, const std::string& signature) const noexcept {
	if (!m_keypair)
		return false;

	try {
		CryptoPP::SecByteBlock pubRaw = KeyPair::DecodeSecBlockBase64(m_keypair->PublicKey());
		CryptoPP::ByteQueue queue;
		queue.Put(pubRaw.data(), pubRaw.size());
		Helpers::SecureWipe(pubRaw);

		CryptoPP::ed25519::Verifier verifier;
		verifier.AccessPublicKey().Load(queue);

		return verifier.VerifyMessage(
			reinterpret_cast<const CryptoPP::byte*>(data.data()),
			data.size_bytes(),
			reinterpret_cast<const CryptoPP::byte*>(signature.data()),
			signature.size()
		);
	} catch (...) {
		return false;
	}
}

bool ED25519::DoVerify(Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	if (!m_keypair)
		return false;

	try {
		CryptoPP::SecByteBlock pubRaw = KeyPair::DecodeSecBlockBase64(m_keypair->PublicKey());
		CryptoPP::ByteQueue queue;
		queue.Put(pubRaw.data(), pubRaw.size());
		Helpers::SecureWipe(pubRaw);

		CryptoPP::ed25519::Verifier verifier;
		verifier.AccessPublicKey().Load(queue);

		bool result = false;
		auto vf = std::unique_ptr<CryptoPP::SignatureVerificationFilter>(
			new CryptoPP::SignatureVerificationFilter(
				verifier,
				new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&result), sizeof(result)),
				CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
			)
		);

		vf->Put(reinterpret_cast<const CryptoPP::byte*>(signature.data()), signature.size());

		constexpr size_t chunkSize = 4096;
		while (!consumer.EoF()) {
			size_t availableBytes = consumer.AvailableBytes();
			if (availableBytes == 0) {
				std::this_thread::yield();
				continue;
			}

			size_t bytesToRead = std::min(availableBytes, chunkSize);
			DataType data;
			bool read_ok = (mode == ReadMode::Copy)
				? consumer.Read(bytesToRead, data)
				: consumer.Extract(bytesToRead, data);
			if (!read_ok)
				return false;

			vf->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
		}

		vf->MessageEnd();
		return result;
	} catch (...) {
		return false;
	}
}
