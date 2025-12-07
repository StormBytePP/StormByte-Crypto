#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/signer/rsa.hxx>
#include <memory>

using namespace StormByte::Crypto::Signer;

bool Generic::DoSign(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);

	if (!read_ok)
		return false;
	
	return DoSign(std::span<const std::byte>(data.data(), data.size()), output);
}

bool Generic::DoVerify(Buffer::ReadOnly& input, const std::string& signature, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);

	if (!read_ok)
		return false;
	
	return DoVerify(std::span<const std::byte>(data.data(), data.size()), signature);
}

namespace StormByte::Crypto::Signer {
	Generic::PointerType Create(Type type, KeyPair::Generic::PointerType keypair) noexcept {
		if (!keypair)
			return nullptr;

		switch (type) {
			case Type::DSA: {
				if (keypair->Type() != KeyPair::Type::DSA)
					return nullptr;
				return std::make_shared<DSA>(keypair);
			}
			case Type::RSA: {
				if (keypair->Type() != KeyPair::Type::RSA)
					return nullptr;
				return std::make_shared<RSA>(keypair);
			}
			case Type::ED25519: {
				if (keypair->Type() != KeyPair::Type::ED25519)
					return nullptr;
				return std::make_shared<ED25519>(keypair);
			}
			case Type::ECDSA:
			default:
				return nullptr;
		}
	}

	Generic::PointerType Create(Type type, const KeyPair::Generic& keypair) noexcept {
		return Create(type, keypair.Clone());
	}

	Generic::PointerType Create(Type type, KeyPair::Generic&& keypair) noexcept {
		return Create(type, keypair.Move());
	}
}