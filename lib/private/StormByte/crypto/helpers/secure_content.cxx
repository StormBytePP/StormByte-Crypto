#include <StormByte/crypto/helpers/secure_content.hxx>

#include <cstring>

using namespace StormByte::Crypto::Helpers;

SecureContent::SecureContent(const void* data, std::size_t size) noexcept
	: m_block(size)
{
	if (size > 0 && data)
		std::memcpy(m_block.data(), data, size);
}

void SecureContent::Wipe() noexcept {
	if (m_block.size() > 0)
		m_block.CleanNew(0);
}

std::size_t SecureContent::Size() const noexcept {
	return m_block.size();
}

const unsigned char* SecureContent::Data() const noexcept {
	return m_block.data();
}

bool SecureContent::Equal(const SecureContent& other) const noexcept {
	if (m_block.size() != other.m_block.size())
		return false;
	unsigned char diff = 0;
	for (std::size_t i = 0; i < m_block.size(); ++i)
		diff |= static_cast<unsigned char>(m_block[i] ^ other.m_block[i]);
	return diff == 0;
}
