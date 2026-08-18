#include <StormByte/crypto/implementation/hasher/details.hxx>

#include <StormByte/buffer/producer.hxx>

#include <thread>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::ReadMode;

namespace StormByte::Crypto::Implementation::Hasher {
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
			ops->Update(data);

			DataType result;
			if (!ops->Finalize(result))
				return false;

			return output.Write(std::move(result));
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

					ops->Update(std::span<const std::byte>(data.data(), data.size()));
				}

				DataType result;
				if (!ops->Finalize(result)) {
					producer.SetError();
					return;
				}

				if (!producer.Write(std::move(result))) {
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