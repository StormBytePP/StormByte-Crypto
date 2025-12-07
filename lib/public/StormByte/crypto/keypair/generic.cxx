#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <fstream>

using namespace StormByte::Crypto::KeyPair;

bool Generic::Save(const std::filesystem::path& path, const std::string& name) const noexcept {
	try {
		// Do not create the directory here — it must already exist and be a directory.
		if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path))
			return false;

		auto make_pem = [](const std::string& b64, const std::string& label) {
			std::string pem;
			pem += "-----BEGIN ";
			pem += label;
			pem += "-----\n";
			for (size_t i = 0; i < b64.size(); i += 64)
				pem += b64.substr(i, 64) + "\n";
			pem += "-----END ";
			pem += label;
			pem += "-----\n";
			return pem;
		};

		// Write public key as PEM
		const auto pubPath = path / (name + std::string(".pem"));
		{
			std::ofstream ofs(pubPath, std::ios::out | std::ios::binary | std::ios::trunc);
			if (!ofs)
				return false;
			ofs << make_pem(m_public_key, "PUBLIC KEY");
		}

		// Write private key if present
		if (m_private_key.has_value()) {
			const auto privPath = path / (name + std::string(".key"));
			std::ofstream ofs(privPath, std::ios::out | std::ios::binary | std::ios::trunc);
			if (!ofs)
				return false;
			ofs << make_pem(*m_private_key, "PRIVATE KEY");
			ofs.close();
			std::error_code ec;
			std::filesystem::permissions(privPath,
				std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
				std::filesystem::perm_options::replace, ec);
		}

		return true;
	} catch (...) {
		return false;
	}
}

namespace StormByte::Crypto::KeyPair {
	Generic::PointerType Create(Type type, unsigned short bits) noexcept {
		switch (type) {
			case Type::DSA:
				return DSA::Generate(bits);
			case Type::ECC:
				return ECC::Generate(bits);
			case Type::ECDH:
				return ECDH::Generate(bits);
			case Type::ECDSA:
				return ECDSA::Generate(bits);
			case Type::ED25519:
				return ED25519::Generate(bits);
			case Type::RSA:
				return RSA::Generate(bits);
			case Type::X25519:
				return X25519::Generate(bits);
			default:
				return nullptr;
		}
	}
}