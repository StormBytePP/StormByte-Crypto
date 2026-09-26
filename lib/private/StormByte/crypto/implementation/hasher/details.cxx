/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

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
