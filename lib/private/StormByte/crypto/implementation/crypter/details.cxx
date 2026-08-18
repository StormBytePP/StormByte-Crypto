#include <StormByte/crypto/implementation/crypter/details.hxx>
#include <StormByte/buffer/producer.hxx>
#include <thread>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::ReadMode;

namespace StormByte::Crypto::Implementation::Crypter {
	namespace {
		constexpr size_t kChunkSize = 4096;
	}

	bool ProcessSpan(std::span<const std::byte> data,
					WriteOnly& output,
					std::unique_ptr<Ops> ops) noexcept
	{
		if (!ops)
			return false;

		try {
			DataType chunk;

			if (!ops->WriteHeader(chunk))
				return false;
			if (!chunk.empty() && !output.Write(std::move(chunk)))
				return false;
			chunk.clear();

			if (!ops->ReadHeader(data))
				return false;

			if (!ops->Process(data, chunk))
				return false;
			if (!chunk.empty() && !output.Write(std::move(chunk)))
				return false;
			chunk.clear();

			if (!ops->Finalize(chunk))
				return false;
			if (!chunk.empty() && !output.Write(std::move(chunk)))
				return false;

			return true;
		} catch (...) {
			return false;
		}
	}

	Consumer Stream(Consumer consumer,
					ReadMode mode,
					std::unique_ptr<Ops> ops) noexcept
	{
		Producer producer;

		if (!ops) {
			producer.SetError();
			return producer.Consumer();
		}

		std::thread([consumer = std::move(consumer),
					producer,
					ops = std::move(ops),
					mode]() mutable
		{
			try {
				DataType outChunk;

				if (!ops->WriteHeader(outChunk)) {
					producer.SetError();
					return;
				}
				if (!outChunk.empty() && !producer.Write(std::move(outChunk))) {
					producer.SetError();
					return;
				}
				outChunk.clear();

				if (!ops->ReadHeader(consumer)) {
					producer.SetError();
					return;
				}

				while (!consumer.EoF()) {
					size_t available = consumer.AvailableBytes();
					if (available == 0) {
						std::this_thread::yield();
						continue;
					}

					size_t toRead = std::min(available, kChunkSize);
					DataType data;
					bool ok = (mode == ReadMode::Copy)
						? consumer.Read(toRead, data)
						: consumer.Extract(toRead, data);

					if (!ok) {
						producer.SetError();
						return;
					}

					if (!ops->Process(
							std::span<const std::byte>(data.data(), data.size()),
							outChunk)) {
						producer.SetError();
						return;
					}

					if (!outChunk.empty() && !producer.Write(std::move(outChunk))) {
						producer.SetError();
						return;
					}
					outChunk.clear();
				}

				if (!ops->Finalize(outChunk)) {
					producer.SetError();
					return;
				}
				if (!outChunk.empty() && !producer.Write(std::move(outChunk))) {
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
