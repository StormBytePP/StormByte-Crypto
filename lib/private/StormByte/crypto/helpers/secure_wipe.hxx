#pragma once

#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <secblock.h>

namespace StormByte::Crypto::Helpers {

	inline void SecureWipe(std::string& s) noexcept {
		if (s.empty()) return;

		volatile char* p = s.data();
		for (size_t i = 0; i < s.size(); ++i) {
			p[i] = 0;
		}
		s.clear();
		s.shrink_to_fit();
	}

	inline void SecureWipe(CryptoPP::SecByteBlock& block) noexcept {
		if (block.empty()) return;
		block.CleanNew(0);
	}

	inline void SecureWipe(std::optional<std::string>& opt) noexcept {
		if (opt.has_value()) {
			SecureWipe(*opt);
			opt.reset();
		}
	}

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
