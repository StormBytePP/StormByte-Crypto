#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/helpers/secure_content.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>

#include <cstring>

using namespace StormByte::Crypto;

namespace {
	struct SecureContentDeleter {
		void operator()(Helpers::SecureContent* ptr) const noexcept {
			if (ptr) {
				ptr->Wipe();
				delete ptr;
			}
		}
	};
}

Password::Password(std::string value) noexcept {
	const std::size_t n = value.size();
	auto* content = new Helpers::SecureContent(value.data(), n);
	Helpers::SecureWipe(value);
	m_data.reset(content, SecureContentDeleter{});
}

Password::Password(const char* value) noexcept {
	const std::size_t n = value ? std::strlen(value) : 0;
	auto* content = new Helpers::SecureContent(value, n);
	m_data.reset(content, SecureContentDeleter{});
}

Password::Password(const void* data, std::size_t size) noexcept {
	auto* content = new Helpers::SecureContent(data, size);
	m_data.reset(content, SecureContentDeleter{});
}

std::size_t Password::Size() const noexcept {
	return m_data ? m_data->Size() : 0;
}

bool Password::Empty() const noexcept {
	return Size() == 0;
}

Password::operator bool() const noexcept {
	return !Empty();
}

bool Password::operator==(const Password& other) const noexcept {
	if (!m_data || !other.m_data)
		return m_data == other.m_data;
	return m_data->Equal(*other.m_data);
}

bool Password::operator!=(const Password& other) const noexcept {
	return !(*this == other);
}
