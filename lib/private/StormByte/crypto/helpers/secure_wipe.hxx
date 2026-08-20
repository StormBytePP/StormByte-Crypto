/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte.
 *
 * StormByte is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * StormByte is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <secblock.h>

namespace StormByte::Crypto::Helpers {

	/**
	 * @brief Securely zero and clear a std::string.
	 * @param s String to wipe.
	 */
	inline void SecureWipe(std::string& s) noexcept {
		if (s.empty()) return;

		volatile char* p = s.data();
		for (size_t i = 0; i < s.size(); ++i) {
			p[i] = 0;
		}
		s.clear();
		s.shrink_to_fit();
	}

	/**
	 * @brief Securely zero a CryptoPP::SecByteBlock.
	 * @param block Block to wipe.
	 */
	inline void SecureWipe(CryptoPP::SecByteBlock& block) noexcept {
		if (block.empty()) return;
		block.CleanNew(0);
	}

	/**
	 * @brief Securely zero an optional string.
	 * @param opt Optional string to wipe.
	 */
	inline void SecureWipe(std::optional<std::string>& opt) noexcept {
		if (opt.has_value()) {
			SecureWipe(*opt);
			opt.reset();
		}
	}

	/**
	 * @brief Securely zero a vector of bytes.
	 * @param data Vector to wipe.
	 */
	inline void SecureWipe(std::vector<std::byte>& data) noexcept {
		if (data.empty()) return;
		volatile std::byte* p = data.data();
		for (size_t i = 0; i < data.size(); ++i) {
			p[i] = std::byte{0};
		}
		data.clear();
		data.shrink_to_fit();
	}
}
