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

#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/string.hxx>

#include <thread>

using StormByte::Buffer::DataType;

StormByte::Buffer::FIFO ReadAllFromConsumer(StormByte::Buffer::Consumer consumer) {
	// Read the decompressed data from the consumer
	StormByte::Buffer::FIFO data;
	while (!consumer.EoF()) {
		size_t available_bytes = consumer.AvailableBytes();
		if (available_bytes == 0) {
			std::this_thread::yield();
			continue;
		}

		DataType d;
		bool read_result = consumer.Read(available_bytes, d);
		if (!read_result) {
			std::cerr << "ReadAllFromConsumer: Read returned false, available=" << available_bytes << " EoF=" << consumer.EoF() << " writable=" << consumer.IsWritable() << std::endl;
			return data;
		}
		if (d.empty()) {
			std::cerr << "ReadAllFromConsumer: read zero bytes despite available=" << available_bytes << std::endl;
		}

		data.Write(std::move(d));
	}
	return data;
}

std::string DeserializeString(const StormByte::Buffer::FIFO& buffer) {
	DataType data;
	bool read_ok = buffer.Read(data);
	if (!read_ok) {
		return {};
	}

	return StormByte::String::FromByteVector(data);
}

// Overload: accept a raw DataType (vector<std::byte>) directly and convert
// to a std::string. Some call sites pass `fifo.Data()` which returns the
// internal `DataType` reference; providing this overload avoids an implicit
// conversion to `FIFO` and is more direct.
inline std::string DeserializeString(const DataType& data) {
	return StormByte::String::FromByteVector(data);
}
