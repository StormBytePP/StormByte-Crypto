#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <hex.h>
#include <filters.h>
#include <secblock.h>
#include <string>
#include <span>
#include <thread>

using StormByte::Buffer::DataType;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

/**
 * @namespace Hasher
 * @brief Namespace for Hasher
 */
namespace StormByte::Crypto::Hasher {
	template<class HasherT>
	STORMBYTE_CRYPTO_PRIVATE bool Hash(std::span<const std::byte> dataSpan, WriteOnly& output) noexcept {
		try {
			HasherT hash;

			// Final digest size
			const size_t digestSize = hash.DigestSize();

			// Compute digest directly using the HasherT interface
			CryptoPP::SecByteBlock digest(digestSize);
			hash.Update(reinterpret_cast<const CryptoPP::byte*>(dataSpan.data()), dataSpan.size_bytes());
			hash.Final(digest);

			// Hex-encode directly into DataType
			DataType hashOutput;
			CryptoPP::HexEncoder encoder(new CryptoPP::StringSinkTemplate<DataType>(hashOutput));
			encoder.Put(digest, digestSize);
			encoder.MessageEnd();

			return output.Write(std::move(hashOutput));
		} catch (...) {
			return false;
		}
	}

	template<class HasherT>
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Hash(Buffer::Consumer consumer, ReadMode mode) noexcept {
		Producer producer;

		std::thread([consumer, producer, mode]() mutable {
			try {
				HasherT hash;

				DataType hashOutput;
				CryptoPP::HexEncoder encoder(new CryptoPP::StringSinkTemplate<DataType>(hashOutput));

				const size_t digestSize = HasherT().DigestSize();
				DataType chunkBuffer(digestSize);
				constexpr size_t chunkSize = 4096;

				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) {
						std::this_thread::yield();
						continue;
					}

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool read_ok;
					if (mode == ReadMode::Copy)
						read_ok = consumer.Read(bytesToRead, data);
					else
						read_ok = consumer.Extract(bytesToRead, data);

					if (!read_ok) {
						producer.SetError();
						return;
					}

					hash.Update(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
				}
				// Finalize the hash
				hash.Final(reinterpret_cast<CryptoPP::byte*>(chunkBuffer.data()));
				encoder.Put(reinterpret_cast<const CryptoPP::byte*>(chunkBuffer.data()), hash.DigestSize());
				encoder.MessageEnd();

				if (!producer.Write(std::move(hashOutput))) {
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
}