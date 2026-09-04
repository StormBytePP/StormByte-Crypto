/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 3
 * or later, as published by the Free Software Foundation.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#include <StormByte/crypto/implementation/compressor/details.hxx>
#include <StormByte/buffer/producer.hxx>
#include <thread>
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::ReadMode;
namespace StormByte::Crypto::Implementation::Compressor {
	namespace {
		constexpr size_t kChunkSize = 4096;
	}
	bool ProcessSpan(std::span<const std::byte> data,
					WriteOnly& output,
					std::unique_ptr<StreamOps> ops) noexcept
	{
		if (!ops)
			return false;
		try {
			DataType total;
			DataType part;
			if (!ops->Process(data, part))
				return false;
			if (!part.empty())
				total.insert(total.end(), part.begin(), part.end());
			part.clear();
			if (!ops->Finalize(part))
				return false;
			if (!part.empty())
				total.insert(total.end(), part.begin(), part.end());
			if (!total.empty() && !output.Write(std::move(total)))
				return false;
			return true;
		} catch (...) {
			return false;
		}
	}
	Consumer Stream(Consumer consumer,
					ReadMode mode,
					std::unique_ptr<StreamOps> ops) noexcept
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
					DataType out;
					if (!ops->Process(
							std::span<const std::byte>(data.data(), data.size()),
							out)) {
						producer.SetError();
						return;
					}
					if (!out.empty() && !producer.Write(std::move(out))) {
						producer.SetError();
						return;
					}
				}
				DataType out;
				if (!ops->Finalize(out)) {
					producer.SetError();
					return;
				}
				if (!out.empty() && !producer.Write(std::move(out))) {
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
