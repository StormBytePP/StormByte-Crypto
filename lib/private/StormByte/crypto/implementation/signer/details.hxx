#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <span>
#include <memory>
#include <string>

namespace StormByte::Crypto::Implementation::Signer {
	/**
	 * @brief Type-erased streaming signer.
	 *
	 * Feed message bytes via Update, then Finalize to obtain the signature.
	 */
	struct SignBox {
		virtual ~SignBox() = default;

		/** @brief Feed one message chunk. */
		virtual bool Update(std::span<const std::byte> in) = 0;

		/**
		 * @brief Finish signing and write the raw signature into @p out.
		 * @return true on success.
		 */
		virtual bool Finalize(Buffer::DataType& out) = 0;
	};

	/**
	 * @brief Type-erased streaming verifier.
	 *
	 * Call Begin(signature) first, then Update with message bytes, then Finalize.
	 */
	struct VerifyBox {
		virtual ~VerifyBox() = default;

		/**
		 * @brief Supply the signature (must be called before any Update).
		 * @return true on success.
		 */
		virtual bool Begin(const std::string& signature) = 0;

		/** @brief Feed one message chunk. */
		virtual bool Update(std::span<const std::byte> in) = 0;

		/**
		 * @brief Finish verification.
		 * @return true if the signature is valid.
		 */
		virtual bool Finalize() = 0;
	};

	/**
	 * @brief One-shot sign: Update(all) + Finalize → write signature to @p output.
	 */
	bool SignSpan(std::span<const std::byte> data,
				Buffer::WriteOnly& output,
				std::unique_ptr<SignBox> box) noexcept;

	/**
	 * @brief Streaming sign: consumes message, produces signature bytes.
	 */
	Buffer::Consumer SignStream(Buffer::Consumer consumer,
								ReadMode mode,
								std::unique_ptr<SignBox> box) noexcept;

	/**
	 * @brief One-shot verify.
	 */
	bool VerifySpan(std::span<const std::byte> data,
					const std::string& signature,
					std::unique_ptr<VerifyBox> box) noexcept;

	/**
	 * @brief Streaming verify (consumes message, returns success/failure).
	 */
	bool VerifyStream(Buffer::Consumer consumer,
					ReadMode mode,
					const std::string& signature,
					std::unique_ptr<VerifyBox> box) noexcept;
}
