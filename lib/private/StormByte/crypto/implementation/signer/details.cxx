#include <StormByte/crypto/implementation/signer/details.hxx>

#include <StormByte/buffer/producer.hxx>

#include <thread>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::ReadMode;

namespace StormByte::Crypto::Implementation::Signer {
    namespace {
        constexpr size_t kChunkSize = 4096;
    }

    bool SignSpan(std::span<const std::byte> data,
                  WriteOnly& output,
                  std::unique_ptr<SignBox> box) noexcept
    {
        if (!box)
            return false;
        try {
            if (!box->Update(data))
                return false;
            DataType signature;
            if (!box->Finalize(signature))
                return false;
            return output.Write(std::move(signature));
        } catch (...) {
            return false;
        }
    }

    Consumer SignStream(Consumer consumer,
                        ReadMode mode,
                        std::unique_ptr<SignBox> box) noexcept
    {
        Producer producer;
        if (!box) {
            producer.SetError();
            return producer.Consumer();
        }

        std::thread([consumer = std::move(consumer),
                     producer,
                     box = std::move(box),
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

                    if (!box->Update(
                            std::span<const std::byte>(data.data(), data.size()))) {
                        producer.SetError();
                        return;
                    }
                }

                DataType signature;
                if (!box->Finalize(signature)) {
                    producer.SetError();
                    return;
                }
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

    bool VerifySpan(std::span<const std::byte> data,
                    const std::string& signature,
                    std::unique_ptr<VerifyBox> box) noexcept
    {
        if (!box)
            return false;
        try {
            if (!box->Begin(signature))
                return false;
            if (!data.empty() && !box->Update(data))
                return false;
            return box->Finalize();
        } catch (...) {
            return false;
        }
    }

    bool VerifyStream(Consumer consumer,
                      ReadMode mode,
                      const std::string& signature,
                      std::unique_ptr<VerifyBox> box) noexcept
    {
        if (!box)
            return false;
        try {
            if (!box->Begin(signature))
                return false;

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
                if (!ok)
                    return false;

                if (!box->Update(
                        std::span<const std::byte>(data.data(), data.size())))
                    return false;
            }

            return box->Finalize();
        } catch (...) {
            return false;
        }
    }
}
