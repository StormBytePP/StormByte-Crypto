#pragma once

#include <StormByte/crypto/implementation/hasher/details.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <hex.h>
#include <filters.h>
#include <secblock.h>
#include <span>
#include <memory>

namespace StormByte::Crypto::Implementation::Hasher {
	/**
	 * @brief One-shot hash (span).
	 *
	 * Thin template that only creates the concrete Ops and delegates
	 * to the non-templated helpers.
	 *
	 * @tparam HasherT Concrete Crypto++ hash type (e.g. CryptoPP::SHA256).
	 * @param dataSpan Input data.
	 * @param output   Destination for the hex-encoded digest.
	 * @return true on success, false on failure.
	 */
	template<class HasherT>
	STORMBYTE_CRYPTO_PRIVATE bool Hash(
		std::span<const std::byte> dataSpan,
		Buffer::WriteOnly& output) noexcept
	{
		struct ConcreteOps final : Ops {
			HasherT hash;

			void Update(std::span<const std::byte> in) override
			{
				hash.Update(
					reinterpret_cast<const CryptoPP::byte*>(in.data()),
					in.size_bytes());
			}

			bool Finalize(Buffer::DataType& out) override
			{
				try {
					const size_t digestSize = hash.DigestSize();
					CryptoPP::SecByteBlock digest(digestSize);
					hash.Final(digest);

					CryptoPP::HexEncoder encoder(
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
					);
					encoder.Put(digest, digestSize);
					encoder.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		return ProcessSpan(dataSpan, output, std::make_unique<ConcreteOps>());
	}

	/**
	 * @brief Streaming hash (Consumer).
	 *
	 * Thin template that only creates the concrete Ops and delegates
	 * to the non-templated streaming helper.
	 *
	 * @tparam HasherT Concrete Crypto++ hash type.
	 * @param consumer Source of input data.
	 * @param mode     Copy or Move semantics.
	 * @return Consumer that yields the final hex-encoded digest.
	 */
	template<class HasherT>
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Hash(
		Buffer::Consumer consumer,
		ReadMode mode) noexcept
	{
		struct ConcreteOps final : Ops {
			HasherT hash;

			void Update(std::span<const std::byte> in) override
			{
				hash.Update(
					reinterpret_cast<const CryptoPP::byte*>(in.data()),
					in.size_bytes());
			}

			bool Finalize(Buffer::DataType& out) override
			{
				try {
					const size_t digestSize = hash.DigestSize();
					CryptoPP::SecByteBlock digest(digestSize);
					hash.Final(digest);

					CryptoPP::HexEncoder encoder(
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
					);
					encoder.Put(digest, digestSize);
					encoder.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		return Stream(std::move(consumer), mode, std::make_unique<ConcreteOps>());
	}
}
