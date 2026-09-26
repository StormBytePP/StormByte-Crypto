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

#include <iostream>
#include <string>
#include <thread>

inline StormByte::Buffer::FIFO ReadAllFromConsumer(StormByte::Buffer::Consumer consumer) {
	StormByte::Buffer::FIFO data;
	while (!consumer.EoF()) {
		const StormByte::ByteSize available = consumer.Available();
		if (available == StormByte::ByteSize{0}) {
			std::this_thread::yield();
			continue;
		}

		StormByte::BinaryData d;
		if (!consumer.Read(available, d)) {
			std::cerr << "ReadAllFromConsumer: Read returned false, EoF=" << consumer.EoF()
				<< " writable=" << consumer.IsWritable() << std::endl;
			return data;
		}
		if (d.empty())
			std::cerr << "ReadAllFromConsumer: read zero bytes despite available data" << std::endl;

		data.Write(std::move(d));
	}
	return data;
}

inline std::string DeserializeString(const StormByte::BinaryData& data) {
	if (data.empty())
		return {};
	return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

inline std::string DeserializeString(const StormByte::Buffer::FIFO& buffer) {
	StormByte::BinaryData data;
	if (!const_cast<StormByte::Buffer::FIFO&>(buffer).Read(StormByte::ByteSize{0}, data))
		return {};
	return DeserializeString(data);
}
