#include <StormByte/crypto/vault.hxx>

using namespace StormByte::Crypto;

Vault::~Vault() noexcept {
	Clear();
}

Vault::Vault(Vault&& other) noexcept
	: m_passwords(std::move(other.m_passwords))
{
	other.m_passwords.clear();
}

Vault& Vault::operator=(Vault&& other) noexcept {
	if (this != &other) {
		Clear();
		m_passwords = std::move(other.m_passwords);
		other.m_passwords.clear();
	}
	return *this;
}

void Vault::Store(std::string name, Password password) noexcept {
	m_passwords.insert_or_assign(std::move(name), std::move(password));
}

ExpectedPassword Vault::Get(const std::string& name) const noexcept {
	auto it = m_passwords.find(name);
	if (it == m_passwords.end()) {
		return StormByte::Unexpected<Exception>("Vault", "Password '{}' not found", name);
	}
	return it->second;
}

bool Vault::Contains(const std::string& name) const noexcept {
	return m_passwords.contains(name);
}

void Vault::Remove(const std::string& name) noexcept {
	m_passwords.erase(name);
}

void Vault::Clear() noexcept {
	m_passwords.clear();
}

std::size_t Vault::Size() const noexcept {
	return m_passwords.size();
}

bool Vault::Empty() const noexcept {
	return m_passwords.empty();
}
