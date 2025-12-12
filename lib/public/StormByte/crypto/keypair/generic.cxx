#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>

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

namespace StormByte::Crypto::KeyPair {
	static std::string ReadFileToString(const std::filesystem::path& p) noexcept {
		try {
			std::ifstream ifs(p, std::ios::in | std::ios::binary);
			if (!ifs)
				return {};
			std::ostringstream ss;
			ss << ifs.rdbuf();
			return ss.str();
		} catch (...) {
			return {};
		}
	}

	static std::string ExtractPemBase64(const std::string& pem) noexcept {
		// Find the first header line "-----BEGIN ...-----" and the corresponding END
		auto begin_pos = pem.find("-----BEGIN");
		if (begin_pos == std::string::npos)
			return {};
		auto begin_nl = pem.find('\n', begin_pos);
		if (begin_nl == std::string::npos)
			begin_nl = pem.find('\r', begin_pos);
		if (begin_nl == std::string::npos)
			return {};
		auto end_pos = pem.find("-----END", begin_nl);
		if (end_pos == std::string::npos)
			return {};
		std::string body = pem.substr(begin_nl + 1, end_pos - (begin_nl + 1));
		// Remove whitespace
		body.erase(std::remove_if(body.begin(), body.end(), [](unsigned char c){ return std::isspace(c); }), body.end());
		return body;
	}

	static std::vector<unsigned char> Base64Decode(const std::string& input) noexcept {
		static const std::string chars =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789+/";
		std::vector<unsigned char> out;
		std::vector<int> T(256, -1);
		for (int i = 0; i < (int)chars.size(); ++i) T[(unsigned char)chars[i]] = i;

		int val = 0, valb = -8;
		for (unsigned char c : input) {
			if (T[c] == -1) break;
			val = (val << 6) + T[c];
			valb += 6;
			if (valb >= 0) {
				out.push_back((unsigned char)((val >> valb) & 0xFF));
				valb -= 8;
			}
		}
		return out;
	}

	Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath) noexcept {
		try {
			const auto pub_str = ReadFileToString(publicKeyPath);
			if (pub_str.empty())
				return nullptr;

			std::string b64 = ExtractPemBase64(pub_str);
			if (b64.empty())
				return nullptr;

			auto der = Base64Decode(b64);
			if (der.empty())
				return nullptr;

			// Known OID byte sequences
			const std::vector<unsigned char> oid_rsa   = {0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01}; // 1.2.840.113549.1.1.1
			const std::vector<unsigned char> oid_ec    = {0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01}; // 1.2.840.10045.2.1
			const std::vector<unsigned char> oid_dsa   = {0x06,0x07,0x2A,0x86,0x48,0xCE,0x38,0x04,0x01}; // 1.2.840.10040.4.1
			const std::vector<unsigned char> oid_ed25519 = {0x06,0x03,0x2B,0x65,0x70}; // 1.3.101.112
			const std::vector<unsigned char> oid_x25519  = {0x06,0x03,0x2B,0x65,0x6E}; // 1.3.101.110

			auto contains = [&](const std::vector<unsigned char>& needle)->bool{
				if (needle.empty() || der.size() < needle.size()) return false;
				for (size_t i = 0; i + needle.size() <= der.size(); ++i) {
					if (std::equal(needle.begin(), needle.end(), der.begin() + i))
						return true;
				}
				return false;
			};

			std::optional<std::string> priv;
			if (!privateKeyPath.empty() && std::filesystem::exists(privateKeyPath)) {
				const auto priv_str = ReadFileToString(privateKeyPath);
				if (!priv_str.empty()) priv = priv_str;
			}

			if (contains(oid_rsa)) {
				return std::make_shared<RSA>(pub_str, priv);
			}
			if (contains(oid_ed25519)) {
				return std::make_shared<ED25519>(pub_str, priv);
			}
			if (contains(oid_x25519)) {
				return std::make_shared<X25519>(pub_str, priv);
			}
			if (contains(oid_dsa)) {
				return std::make_shared<DSA>(pub_str, priv);
			}
			if (contains(oid_ec)) {
				// Use generic ECC for EC keys (covers ECDSA/ECDH)
				return std::make_shared<ECC>(pub_str, priv);
			}

			return nullptr;
		} catch (...) {
			return nullptr;
		}
	}
}