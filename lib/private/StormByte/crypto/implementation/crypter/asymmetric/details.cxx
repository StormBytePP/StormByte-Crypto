#include <StormByte/crypto/implementation/crypter/asymmetric/details.hxx>

#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/buffer/producer.hxx>

#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <thread>
#include <cstring>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::ReadMode;
using StormByte::Crypto::Helpers::SecureWipe;

namespace StormByte::Crypto::Implementation::Crypter::Asymmetric {
	// -------------------------------------------------------------------------
	// Small helpers
	// -------------------------------------------------------------------------

	bool WriteEnvelopeHeader(const DataType& esk,
							const CryptoPP::SecByteBlock& iv,
							DataType& out) noexcept
	{
		try {
			const uint32_t eskLen = static_cast<uint32_t>(esk.size());
			out.reserve(4 + esk.size() + iv.size());
			out.push_back(static_cast<std::byte>((eskLen >> 24) & 0xFF));
			out.push_back(static_cast<std::byte>((eskLen >> 16) & 0xFF));
			out.push_back(static_cast<std::byte>((eskLen >> 8) & 0xFF));
			out.push_back(static_cast<std::byte>(eskLen & 0xFF));
			out.insert(out.end(), esk.begin(), esk.end());
			for (size_t i = 0; i < iv.size(); ++i)
				out.push_back(static_cast<std::byte>(iv[i]));
			return true;
		} catch (...) {
			return false;
		}
	}

	std::uint32_t ParseEskLength(const DataType& lenBytes) noexcept
	{
		if (lenBytes.size() != 4)
			return 0;
		return (static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[0])) << 24) |
			(static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[1])) << 16) |
			(static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[2])) << 8)  |
			(static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[3])));
	}

	// -------------------------------------------------------------------------
	// Native
	// -------------------------------------------------------------------------

	namespace {
		struct NativeOps final : Crypter::Ops {
			std::unique_ptr<PkBox> box;

			explicit NativeOps(std::unique_ptr<PkBox> b)
				: box(std::move(b)) {}

			bool Process(std::span<const std::byte> in, DataType& outChunk) override
			{
				return box && box->Transform(in, outChunk);
			}

			bool Finalize(DataType& /*outChunk*/) override
			{
				return true;
			}
		};
	}

	bool NativeProcessSpan(std::span<const std::byte> data,
						WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept
	{
		if (!box)
			return false;
		return Crypter::ProcessSpan(
			data, output, std::make_unique<NativeOps>(std::move(box)));
	}

	Consumer NativeProcessStream(Consumer consumer,
								ReadMode mode,
								std::unique_ptr<PkBox> box) noexcept
	{
		if (!box) {
			Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return Crypter::Stream(
			std::move(consumer), mode,
			std::make_unique<NativeOps>(std::move(box)));
	}

	// -------------------------------------------------------------------------
	// Hybrid encrypt
	// -------------------------------------------------------------------------

	namespace {
		struct HybridEncryptOps final : Crypter::Ops {
			std::unique_ptr<PkBox> box;
			CryptoPP::SecByteBlock symKey, iv;
			CryptoPP::GCM<CryptoPP::AES>::Encryption aead;
			DataType buffer;
			std::unique_ptr<CryptoPP::AuthenticatedEncryptionFilter> filter;
			bool streaming;

			HybridEncryptOps(std::unique_ptr<PkBox> b, bool stream)
				: box(std::move(b)), streaming(stream) {}

			~HybridEncryptOps() override
			{
				SecureWipe(symKey);
				SecureWipe(iv);
			}

			bool WriteHeader(DataType& outChunk) override
			{
				if (!box)
					return false;
				try {
					symKey.CleanNew(kSymKeyLen);
					iv.CleanNew(kIvLen);
					RNG().GenerateBlock(symKey, symKey.size());
					RNG().GenerateBlock(iv, iv.size());

					DataType esk;
					if (!box->Transform(
							std::span<const std::byte>(
								reinterpret_cast<const std::byte*>(symKey.data()),
								symKey.size()),
							esk))
						return false;

					if (!WriteEnvelopeHeader(esk, iv, outChunk))
						return false;
					SecureWipe(esk);

					aead.SetKeyWithIV(symKey, symKey.size(), iv, iv.size());

					if (streaming) {
						filter = std::make_unique<CryptoPP::AuthenticatedEncryptionFilter>(
							aead,
							new CryptoPP::StringSinkTemplate<DataType>(buffer)
						);
					}
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, DataType& outChunk) override
			{
				try {
					if (streaming) {
						filter->Put(
							reinterpret_cast<const CryptoPP::byte*>(in.data()),
							in.size_bytes());
						outChunk = std::move(buffer);
						buffer.clear();
						return true;
					}

					CryptoPP::AuthenticatedEncryptionFilter ef(
						aead,
						new CryptoPP::StringSinkTemplate<DataType>(outChunk)
					);
					ef.Put(
						reinterpret_cast<const CryptoPP::byte*>(in.data()),
						in.size_bytes());
					ef.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(DataType& outChunk) override
			{
				if (!streaming)
					return true;
				try {
					filter->MessageEnd();
					outChunk = std::move(buffer);
					buffer.clear();
					filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}
		};
	}

	bool HybridEncryptSpan(std::span<const std::byte> data,
						WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept
	{
		if (!box)
			return false;
		return Crypter::ProcessSpan(
			data, output,
			std::make_unique<HybridEncryptOps>(std::move(box), false));
	}

	Consumer HybridEncryptStream(Consumer consumer,
								ReadMode mode,
								std::unique_ptr<PkBox> box) noexcept
	{
		if (!box) {
			Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return Crypter::Stream(
			std::move(consumer), mode,
			std::make_unique<HybridEncryptOps>(std::move(box), true));
	}

	// -------------------------------------------------------------------------
	// Hybrid decrypt
	// -------------------------------------------------------------------------

	namespace {
		struct HybridDecryptOps final : Crypter::Ops {
			std::unique_ptr<PkBox> box;
			ReadMode mode;
			CryptoPP::SecByteBlock iv, symKey;
			CryptoPP::GCM<CryptoPP::AES>::Decryption aead;
			DataType buffer;
			std::unique_ptr<CryptoPP::AuthenticatedDecryptionFilter> filter;
			bool streaming;

			HybridDecryptOps(std::unique_ptr<PkBox> b, ReadMode m, bool stream)
				: box(std::move(b)), mode(m), streaming(stream) {}

			~HybridDecryptOps() override
			{
				SecureWipe(symKey);
				SecureWipe(iv);
			}

			bool ReadHeader(std::span<const std::byte>& in) override
			{
				if (!box || in.size_bytes() < 4)
					return false;
				try {
					const uint32_t esk_len =
						(static_cast<uint32_t>(std::to_integer<unsigned char>(in[0])) << 24) |
						(static_cast<uint32_t>(std::to_integer<unsigned char>(in[1])) << 16) |
						(static_cast<uint32_t>(std::to_integer<unsigned char>(in[2])) << 8)  |
						(static_cast<uint32_t>(std::to_integer<unsigned char>(in[3])));

					size_t pos = 4;
					if (in.size_bytes() < pos + esk_len + kIvLen)
						return false;

					DataType eskData(esk_len);
					std::memcpy(eskData.data(), in.data() + pos, esk_len);
					pos += esk_len;

					iv.CleanNew(kIvLen);
					std::memcpy(iv.data(), in.data() + pos, kIvLen);
					pos += kIvLen;
					in = in.subspan(pos);

					DataType symKeyData;
					if (!box->Transform(
							std::span<const std::byte>(eskData.data(), eskData.size()),
							symKeyData)) {
						SecureWipe(eskData);
						return false;
					}
					SecureWipe(eskData);

					if (symKeyData.empty())
						return false;

					symKey.Assign(
						reinterpret_cast<const CryptoPP::byte*>(symKeyData.data()),
						symKeyData.size());
					SecureWipe(symKeyData);

					aead.SetKeyWithIV(symKey, symKey.size(), iv, kIvLen);
					return true;
				} catch (...) {
					return false;
				}
			}

			bool ReadHeader(Consumer& consumer) override
			{
				if (!box)
					return false;
				try {
					while (consumer.AvailableBytes() < 4 && !consumer.EoF())
						std::this_thread::yield();
					if (consumer.AvailableBytes() < 4)
						return false;

					DataType lenBytes;
					bool ok = (mode == ReadMode::Copy)
						? consumer.Read(4, lenBytes)
						: consumer.Extract(4, lenBytes);
					if (!ok || lenBytes.size() != 4)
						return false;

					const uint32_t esk_len = ParseEskLength(lenBytes);
					const size_t headerRest = static_cast<size_t>(esk_len) + kIvLen;

					while (consumer.AvailableBytes() < headerRest && !consumer.EoF())
						std::this_thread::yield();
					if (consumer.AvailableBytes() < headerRest)
						return false;

					DataType eskData;
					ok = (mode == ReadMode::Copy)
						? consumer.Read(esk_len, eskData)
						: consumer.Extract(esk_len, eskData);
					if (!ok || eskData.size() != esk_len)
						return false;

					DataType ivData;
					ok = (mode == ReadMode::Copy)
						? consumer.Read(kIvLen, ivData)
						: consumer.Extract(kIvLen, ivData);
					if (!ok || ivData.size() != kIvLen) {
						SecureWipe(eskData);
						return false;
					}

					iv.CleanNew(kIvLen);
					std::memcpy(iv.data(), ivData.data(), kIvLen);
					SecureWipe(ivData);

					DataType symKeyData;
					if (!box->Transform(
							std::span<const std::byte>(eskData.data(), eskData.size()),
							symKeyData)) {
						SecureWipe(eskData);
						return false;
					}
					SecureWipe(eskData);

					if (symKeyData.empty())
						return false;

					symKey.Assign(
						reinterpret_cast<const CryptoPP::byte*>(symKeyData.data()),
						symKeyData.size());
					SecureWipe(symKeyData);

					aead.SetKeyWithIV(symKey, symKey.size(), iv, kIvLen);
					filter = std::make_unique<CryptoPP::AuthenticatedDecryptionFilter>(
						aead,
						new CryptoPP::StringSinkTemplate<DataType>(buffer),
						CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
					);
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Process(std::span<const std::byte> in, DataType& outChunk) override
			{
				try {
					if (streaming) {
						filter->Put(
							reinterpret_cast<const CryptoPP::byte*>(in.data()),
							in.size_bytes());
						outChunk = std::move(buffer);
						buffer.clear();
						return true;
					}

					CryptoPP::AuthenticatedDecryptionFilter df(
						aead,
						new CryptoPP::StringSinkTemplate<DataType>(outChunk),
						CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
					);
					if (!in.empty())
						df.Put(
							reinterpret_cast<const CryptoPP::byte*>(in.data()),
							in.size_bytes());
					df.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(DataType& outChunk) override
			{
				if (!streaming)
					return true;
				try {
					filter->MessageEnd();
					outChunk = std::move(buffer);
					buffer.clear();
					filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}
		};
	}

	bool HybridDecryptSpan(std::span<const std::byte> data,
						WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept
	{
		if (!box)
			return false;
		return Crypter::ProcessSpan(
			data, output,
			std::make_unique<HybridDecryptOps>(std::move(box), ReadMode::Copy, false));
	}

	Consumer HybridDecryptStream(Consumer consumer,
								ReadMode mode,
								std::unique_ptr<PkBox> box) noexcept
	{
		if (!box) {
			Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return Crypter::Stream(
			std::move(consumer), mode,
			std::make_unique<HybridDecryptOps>(std::move(box), mode, true));
	}
}
