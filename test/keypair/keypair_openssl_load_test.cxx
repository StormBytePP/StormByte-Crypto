#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/test_handlers.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using namespace StormByte::Crypto;
using StormByte::Buffer::FIFO;
namespace fs = std::filesystem;

#ifndef STORMBYTE_TEST_KEYS_DIR
#error "STORMBYTE_TEST_KEYS_DIR must be defined by CMake"
#endif

#ifndef STORMBYTE_TEST_KEYS_PASSWORD
#error "STORMBYTE_TEST_KEYS_PASSWORD must be defined by CMake"
#endif

namespace {
	fs::path KeysDir() {
		return fs::path(STORMBYTE_TEST_KEYS_DIR);
	}

	fs::path KeyFile(const std::string& name) {
		return KeysDir() / name;
	}

	bool FileExists(const fs::path& p) {
		return fs::exists(p) && fs::is_regular_file(p);
	}

	const std::string kPlainText = "StormByte OpenSSL key interop test payload";

	Password TestKeysPassword() {
		return Password(STORMBYTE_TEST_KEYS_PASSWORD);
	}

	static bool WriteBytes(const fs::path& path, const std::vector<unsigned char>& data) {
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		if (!ofs)
			return false;
		if (!data.empty())
			ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
		return static_cast<bool>(ofs);
	}

	static bool WriteText(const fs::path& path, const std::string& text) {
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		if (!ofs)
			return false;
		ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
		return static_cast<bool>(ofs);
	}

	static std::vector<unsigned char> ReadAllBytes(const fs::path& path) {
		std::ifstream ifs(path, std::ios::binary);
		if (!ifs)
			return {};
		return std::vector<unsigned char>(
			(std::istreambuf_iterator<char>(ifs)),
			std::istreambuf_iterator<char>()
		);
	}

	static std::string ReadAllText(const fs::path& path) {
		std::ifstream ifs(path, std::ios::binary);
		if (!ifs)
			return {};
		return std::string(
			(std::istreambuf_iterator<char>(ifs)),
			std::istreambuf_iterator<char>()
		);
	}
}

// ---------------------------------------------------------------------------
// Helpers: load OpenSSL fixtures
// ---------------------------------------------------------------------------

int AssertLoadPair(const std::string& fn_name, const std::string& pubName, const std::string& privName,
		KeyPair::Generic::PointerType& out, KeyPair::Type expectedType, bool checkTypeStrict = true) {
	const auto pub = KeyFile(pubName);
	const auto priv = KeyFile(privName);
	ASSERT_TRUE(fn_name, FileExists(pub));
	ASSERT_TRUE(fn_name, FileExists(priv));

	out = KeyPair::Load(pub, priv);
	ASSERT_TRUE(fn_name, out);
	ASSERT_TRUE(fn_name, out->HasPrivateKey());
	ASSERT_TRUE(fn_name, !out->PublicKey().empty());
	if (checkTypeStrict) {
		ASSERT_TRUE(fn_name, out->Type() == expectedType);
	}
	return 0;
}

// ---------------------------------------------------------------------------
// RSA: Load → Encrypt/Decrypt → Sign/Verify
// ---------------------------------------------------------------------------

int TestOpenSslRsaEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslRsaEncryptDecrypt";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "rsa_test.pub.pem", "rsa_test.priv.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;

	Crypter::RSA crypter(kp);

	FIFO encrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, !encrypted.Data().empty());

	auto encStr = std::string(reinterpret_cast<const char*>(encrypted.Data().data()), encrypted.Data().size());
	ASSERT_NOT_EQUAL(fn_name, encStr, kPlainText);

	FIFO decrypted;
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaHybridEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslRsaHybridEncryptDecrypt";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "rsa_test.pub.pem", "rsa_test.priv.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;

	Crypter::RSA crypter(kp);
	const std::string longText = kPlainText + std::string(4096, 'A');

	FIFO encrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(longText.data()), longText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Hybrid
	));
	ASSERT_TRUE(fn_name, !encrypted.Data().empty());

	FIFO decrypted;
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, longText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaSignVerify() {
	const std::string fn_name = "TestOpenSslRsaSignVerify";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "rsa_test.pub.pem", "rsa_test.priv.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;

	Signer::RSA signer(kp);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	ASSERT_TRUE(fn_name, !signature.Data().empty());

	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	const std::string tampered = kPlainText + "X";
	ASSERT_FALSE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(tampered.data()), tampered.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaDerRoundTripUse() {
	const std::string fn_name = "TestOpenSslRsaDerRoundTripUse";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "rsa_test.pub.der", "rsa_test.priv.der", kp, KeyPair::Type::RSA) != 0)
		return 1;

	Crypter::RSA crypter(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// DSA: Load → Sign/Verify
// ---------------------------------------------------------------------------

int TestOpenSslDsaSignVerify() {
	const std::string fn_name = "TestOpenSslDsaSignVerify";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "dsa_test.pub.pem", "dsa_test.priv.pem", kp, KeyPair::Type::DSA) != 0)
		return 1;

	Signer::DSA signer(kp);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	ASSERT_TRUE(fn_name, !signature.Data().empty());

	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	ASSERT_FALSE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>("other"), 5),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// ECDSA: Load → Sign/Verify
// ---------------------------------------------------------------------------

int TestOpenSslEcdsaSignVerify() {
	const std::string fn_name = "TestOpenSslEcdsaSignVerify";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "ecdsa_test.pub.pem", "ecdsa_test.priv.pem", kp, KeyPair::Type::ECDSA, false) != 0)
		return 1;

	Signer::ECDSA signer(kp);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	ASSERT_TRUE(fn_name, !signature.Data().empty());

	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// ECC: Load → Encrypt/Decrypt
// ---------------------------------------------------------------------------

int TestOpenSslEccEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslEccEncryptDecrypt";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "ecc_p256_test.pub.pem", "ecc_p256_test.priv.pem", kp, KeyPair::Type::ECC, false) != 0)
		return 1;

	Crypter::ECC crypter(kp);

	FIFO encrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, !encrypted.Data().empty());

	FIFO decrypted;
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Ed25519: Load → Sign/Verify
// ---------------------------------------------------------------------------

int TestOpenSslEd25519SignVerify() {
	const std::string fn_name = "TestOpenSslEd25519SignVerify";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "ed25519_test.pub.pem", "ed25519_test.priv.pem", kp, KeyPair::Type::ED25519) != 0)
		return 1;

	Signer::ED25519 signer(kp);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	ASSERT_TRUE(fn_name, !signature.Data().empty());

	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	ASSERT_FALSE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>("tampered"), 8),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEd25519DerSignVerify() {
	const std::string fn_name = "TestOpenSslEd25519DerSignVerify";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "ed25519_test.pub.der", "ed25519_test.priv.der", kp, KeyPair::Type::ED25519) != 0)
		return 1;

	Signer::ED25519 signer(kp);
	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// ECDH: Load local + peer → Share (same secret both ways)
// ---------------------------------------------------------------------------

int TestOpenSslEcdhShare() {
	const std::string fn_name = "TestOpenSslEcdhShare";

	// Control: library-generated keys must Share (baseline)
	{
		auto a = KeyPair::ECDH::Generate(256);
		auto b = KeyPair::ECDH::Generate(256);
		ASSERT_TRUE(fn_name, a && b);
		Secret::ECDH sa(a);
		Secret::ECDH sb(b);
		auto s1 = sa.Share(b->PublicKey());
		auto s2 = sb.Share(a->PublicKey());
		ASSERT_TRUE(fn_name, s1.has_value());
		ASSERT_TRUE(fn_name, s2.has_value());
		ASSERT_TRUE(fn_name, s1 == s2);
	}

	auto localLoaded = KeyPair::Load(KeyFile("ecdh_test.pub.pem"), KeyFile("ecdh_test.priv.pem"));
	auto peerLoaded  = KeyPair::Load(KeyFile("ecdh_peer_test.pub.pem"), KeyFile("ecdh_peer_test.priv.pem"));
	ASSERT_TRUE(fn_name, localLoaded);
	ASSERT_TRUE(fn_name, peerLoaded);
	ASSERT_TRUE(fn_name, localLoaded->HasPrivateKey());
	ASSERT_TRUE(fn_name, peerLoaded->HasPrivateKey());

	// Optional: see if formats look like Generate (Base64 length / type)
	// std::cerr << "type=" << (int)localLoaded->Type()
	//           << " pubLen=" << localLoaded->PublicKey().size() << "\n";

	auto local = std::make_shared<KeyPair::ECDH>(localLoaded->PublicKey(), localLoaded->PrivateKey());
	auto peer  = std::make_shared<KeyPair::ECDH>(peerLoaded->PublicKey(), peerLoaded->PrivateKey());

	Secret::ECDH ecdhLocal(local);
	Secret::ECDH ecdhPeer(peer);

	auto s1 = ecdhLocal.Share(peer->PublicKey());
	auto s2 = ecdhPeer.Share(local->PublicKey());

	// Which of these fails? has_value vs equality
	ASSERT_TRUE(fn_name, s1.has_value());  // line ~353 if this is the one
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);
	ASSERT_TRUE(fn_name, !s1->Empty());

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslX25519Share() {
	const std::string fn_name = "TestOpenSslX25519Share";

	auto localLoaded = KeyPair::Load(KeyFile("x25519_test.pub.pem"), KeyFile("x25519_test.priv.pem"));
	auto peerLoaded  = KeyPair::Load(KeyFile("x25519_peer_test.pub.pem"), KeyFile("x25519_peer_test.priv.pem"));
	ASSERT_TRUE(fn_name, localLoaded);
	ASSERT_TRUE(fn_name, peerLoaded);

	auto local = std::make_shared<KeyPair::X25519>(localLoaded->PublicKey(), localLoaded->PrivateKey());
	auto peer  = std::make_shared<KeyPair::X25519>(peerLoaded->PublicKey(), peerLoaded->PrivateKey());

	Secret::X25519 xLocal(local);
	Secret::X25519 xPeer(peer);

	auto s1 = xLocal.Share(peer->PublicKey());
	auto s2 = xPeer.Share(local->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);
	ASSERT_TRUE(fn_name, !s1->Empty());

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Single-file load still usable
// ---------------------------------------------------------------------------

int TestOpenSslRsaPrivateOnlyThenEncrypt() {
	const std::string fn_name = "TestOpenSslRsaPrivateOnlyThenEncrypt";
	const auto priv = KeyFile("rsa_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(priv));

	auto kp = KeyPair::Load(priv);
	ASSERT_TRUE(fn_name, kp);
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !kp->PublicKey().empty());

	Crypter::RSA crypter(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Library Save → Load → still works
// ---------------------------------------------------------------------------

int TestLibraryRsaSaveLoadStillEncrypts() {
	const std::string fn_name = "TestLibraryRsaSaveLoadStillEncrypts";
	auto original = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, original);

	const fs::path outDir = KeysDir() / "roundtrip";
	fs::create_directories(outDir);
	ASSERT_TRUE(fn_name, original->Save(outDir, "lib_rsa", KeyPair::StorageFormat::PEM));

	auto loaded = KeyPair::Load(outDir / "lib_rsa.pub.pem", outDir / "lib_rsa.pem");
	ASSERT_TRUE(fn_name, loaded);

	Crypter::RSA crypter(loaded);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Encrypted PEM without password must fail
// ---------------------------------------------------------------------------

int TestOpenSslEncryptedPrivateWithoutPasswordFails() {
	const std::string fn_name = "TestOpenSslEncryptedPrivateWithoutPasswordFails";
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	ASSERT_TRUE(fn_name, FileExists(enc));
	ASSERT_FALSE(fn_name, KeyPair::Load(enc));
	ASSERT_FALSE(fn_name, KeyPair::Load(KeyFile("rsa_test.pub.pem"), enc));

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Private-only Load: derived public must work as a standalone public key
// ---------------------------------------------------------------------------

int TestOpenSslRsaPrivateOnlyDerivesPublic() {
	const std::string fn_name = "TestOpenSslRsaPrivateOnlyDerivesPublic";
	const auto privPath = KeyFile("rsa_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(privPath));

	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(fn_name, privKp);
	ASSERT_TRUE(fn_name, privKp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !privKp->PublicKey().empty());

	// Public-only keypair built from derived public (no private)
	auto pubKp = std::make_shared<KeyPair::RSA>(privKp->PublicKey(), std::nullopt);
	ASSERT_FALSE(fn_name, pubKp->HasPrivateKey());

	Crypter::RSA encryptor(pubKp);
	Crypter::RSA decryptor(privKp);

	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, encryptor.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, decryptor.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslDsaPrivateOnlyDerivesPublic() {
	const std::string fn_name = "TestOpenSslDsaPrivateOnlyDerivesPublic";
	const auto privPath = KeyFile("dsa_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(privPath));

	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(fn_name, privKp);
	ASSERT_TRUE(fn_name, privKp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !privKp->PublicKey().empty());

	auto pubKp = std::make_shared<KeyPair::DSA>(privKp->PublicKey(), std::nullopt);
	ASSERT_FALSE(fn_name, pubKp->HasPrivateKey());

	Signer::DSA signer(privKp);
	Signer::DSA verifier(pubKp);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, verifier.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdsaPrivateOnlyDerivesPublic() {
	const std::string fn_name = "TestOpenSslEcdsaPrivateOnlyDerivesPublic";
	const auto privPath = KeyFile("ecdsa_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(privPath));

	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(fn_name, privKp);
	ASSERT_TRUE(fn_name, privKp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !privKp->PublicKey().empty());

	auto pubKp = std::make_shared<KeyPair::ECDSA>(privKp->PublicKey(), std::nullopt);
	ASSERT_FALSE(fn_name, pubKp->HasPrivateKey());

	Signer::ECDSA signer(privKp);
	Signer::ECDSA verifier(pubKp);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, verifier.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEccPrivateOnlyDerivesPublic() {
	const std::string fn_name = "TestOpenSslEccPrivateOnlyDerivesPublic";
	const auto privPath = KeyFile("ecc_p256_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(privPath));

	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(fn_name, privKp);
	ASSERT_TRUE(fn_name, privKp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !privKp->PublicKey().empty());

	auto pubKp = std::make_shared<KeyPair::ECC>(privKp->PublicKey(), std::nullopt);
	ASSERT_FALSE(fn_name, pubKp->HasPrivateKey());

	Crypter::ECC encryptor(pubKp);
	Crypter::ECC decryptor(privKp);

	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, encryptor.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, decryptor.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEd25519PrivateOnlyDerivesPublic() {
	const std::string fn_name = "TestOpenSslEd25519PrivateOnlyDerivesPublic";
	const auto privPath = KeyFile("ed25519_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(privPath));

	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(fn_name, privKp);
	ASSERT_TRUE(fn_name, privKp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !privKp->PublicKey().empty());

	auto pubKp = std::make_shared<KeyPair::ED25519>(privKp->PublicKey(), std::nullopt);
	ASSERT_FALSE(fn_name, pubKp->HasPrivateKey());

	Signer::ED25519 signer(privKp);
	Signer::ED25519 verifier(pubKp);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, verifier.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdhPrivateOnlyDerivesPublic() {
	const std::string fn_name = "TestOpenSslEcdhPrivateOnlyDerivesPublic";
	const auto privPath = KeyFile("ecdh_test.priv.pem");
	const auto peerPriv = KeyFile("ecdh_peer_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(privPath));
	ASSERT_TRUE(fn_name, FileExists(peerPriv));

	auto localPriv = KeyPair::Load(privPath);
	auto peerPrivKp = KeyPair::Load(peerPriv);
	ASSERT_TRUE(fn_name, localPriv);
	ASSERT_TRUE(fn_name, peerPrivKp);
	ASSERT_TRUE(fn_name, !localPriv->PublicKey().empty());
	ASSERT_TRUE(fn_name, !peerPrivKp->PublicKey().empty());

	// Peer's derived public only (no private on that object) must still agree
	auto peerPubOnly = std::make_shared<KeyPair::ECDH>(peerPrivKp->PublicKey(), std::nullopt);
	ASSERT_FALSE(fn_name, peerPubOnly->HasPrivateKey());

	auto local = std::make_shared<KeyPair::ECDH>(localPriv->PublicKey(), localPriv->PrivateKey());
	auto peer  = std::make_shared<KeyPair::ECDH>(peerPrivKp->PublicKey(), peerPrivKp->PrivateKey());

	Secret::ECDH a(local, 256);
	Secret::ECDH b(peer, 256);

	// Share using only the peer's public string (derived), not a loaded .pub file
	auto s1 = a.Share(peerPubOnly->PublicKey());
	auto s2 = b.Share(local->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslX25519PrivateOnlyDerivesPublic() {
	const std::string fn_name = "TestOpenSslX25519PrivateOnlyDerivesPublic";
	const auto privPath = KeyFile("x25519_test.priv.pem");
	const auto peerPriv = KeyFile("x25519_peer_test.priv.pem");
	ASSERT_TRUE(fn_name, FileExists(privPath));
	ASSERT_TRUE(fn_name, FileExists(peerPriv));

	auto localPriv = KeyPair::Load(privPath);
	auto peerPrivKp = KeyPair::Load(peerPriv);
	ASSERT_TRUE(fn_name, localPriv);
	ASSERT_TRUE(fn_name, peerPrivKp);
	ASSERT_TRUE(fn_name, !localPriv->PublicKey().empty());
	ASSERT_TRUE(fn_name, !peerPrivKp->PublicKey().empty());

	auto peerPubOnly = std::make_shared<KeyPair::X25519>(peerPrivKp->PublicKey(), std::nullopt);
	ASSERT_FALSE(fn_name, peerPubOnly->HasPrivateKey());

	Secret::X25519 xLocal(localPriv);
	Secret::X25519 xPeer(peerPrivKp);

	auto s1 = xLocal.Share(peerPubOnly->PublicKey());
	auto s2 = xPeer.Share(localPriv->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Encrypted private key Load (password) → usable for crypto ops
// ---------------------------------------------------------------------------

int TestOpenSslRsaEncryptedLoadEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslRsaEncryptedLoadEncryptDecrypt";
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	const auto pub = KeyFile("rsa_test.pub.pem");
	ASSERT_TRUE(fn_name, FileExists(enc));
	ASSERT_TRUE(fn_name, FileExists(pub));

	Password pass = TestKeysPassword();
	auto kp = KeyPair::Load(pub, enc, pass);
	ASSERT_TRUE(fn_name, kp);
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !kp->PublicKey().empty());

	auto pubOnly = std::make_shared<KeyPair::RSA>(kp->PublicKey(), std::nullopt);
	Crypter::RSA encryptor(pubOnly);
	Crypter::RSA decryptor(kp);

	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, encryptor.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, decryptor.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaEncryptedLoadPrivateOnly() {
	const std::string fn_name = "TestOpenSslRsaEncryptedLoadPrivateOnly";
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	ASSERT_TRUE(fn_name, FileExists(enc));

	Password pass = TestKeysPassword();
	auto kp = KeyPair::Load(enc, pass);
	ASSERT_TRUE(fn_name, kp);
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !kp->PublicKey().empty());

	auto pubOnly = std::make_shared<KeyPair::RSA>(kp->PublicKey(), std::nullopt);
	Crypter::RSA encryptor(pubOnly);
	Crypter::RSA decryptor(kp);

	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, encryptor.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, decryptor.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaEncryptedWrongPasswordFails() {
	const std::string fn_name = "TestOpenSslRsaEncryptedWrongPasswordFails";
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	ASSERT_TRUE(fn_name, FileExists(enc));

	Password wrong("DefinitelyNotTheRightPassphrase");
	ASSERT_FALSE(fn_name, KeyPair::Load(enc, wrong));
	ASSERT_FALSE(fn_name, KeyPair::Load(KeyFile("rsa_test.pub.pem"), enc, wrong));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaEncryptedSignVerify() {
	const std::string fn_name = "TestOpenSslRsaEncryptedSignVerify";
	Password pass = TestKeysPassword();
	auto kp = KeyPair::Load(KeyFile("rsa_test.priv.enc.pem"), pass);
	ASSERT_TRUE(fn_name, kp);

	auto pubOnly = std::make_shared<KeyPair::RSA>(kp->PublicKey(), std::nullopt);
	Signer::RSA signer(kp);
	Signer::RSA verifier(pubOnly);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, verifier.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslDsaEncryptedSignVerify() {
	const std::string fn_name = "TestOpenSslDsaEncryptedSignVerify";
	Password pass = TestKeysPassword();
	auto kp = KeyPair::Load(KeyFile("dsa_test.priv.enc.pem"), pass);
	ASSERT_TRUE(fn_name, kp);

	auto pubOnly = std::make_shared<KeyPair::DSA>(kp->PublicKey(), std::nullopt);
	Signer::DSA signer(kp);
	Signer::DSA verifier(pubOnly);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, verifier.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdsaEncryptedSignVerify() {
	const std::string fn_name = "TestOpenSslEcdsaEncryptedSignVerify";
	Password pass = TestKeysPassword();
	auto kp = KeyPair::Load(KeyFile("ecdsa_test.priv.enc.pem"), pass);
	ASSERT_TRUE(fn_name, kp);

	auto pubOnly = std::make_shared<KeyPair::ECDSA>(kp->PublicKey(), std::nullopt);
	Signer::ECDSA signer(kp);
	Signer::ECDSA verifier(pubOnly);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, verifier.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEccEncryptedEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslEccEncryptedEncryptDecrypt";
	Password pass = TestKeysPassword();
	auto kp = KeyPair::Load(KeyFile("ecc_p256_test.priv.enc.pem"), pass);
	ASSERT_TRUE(fn_name, kp);

	auto pubOnly = std::make_shared<KeyPair::ECC>(kp->PublicKey(), std::nullopt);
	Crypter::ECC encryptor(pubOnly);
	Crypter::ECC decryptor(kp);

	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, encryptor.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, decryptor.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEd25519EncryptedSignVerify() {
	const std::string fn_name = "TestOpenSslEd25519EncryptedSignVerify";
	Password pass = TestKeysPassword();
	auto kp = KeyPair::Load(KeyFile("ed25519_test.priv.enc.pem"), pass);
	ASSERT_TRUE(fn_name, kp);

	auto pubOnly = std::make_shared<KeyPair::ED25519>(kp->PublicKey(), std::nullopt);
	Signer::ED25519 signer(kp);
	Signer::ED25519 verifier(pubOnly);

	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	const std::string sigStr(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size());
	ASSERT_TRUE(fn_name, verifier.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		sigStr
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdhEncryptedShare() {
	const std::string fn_name = "TestOpenSslEcdhEncryptedShare";
	Password pass = TestKeysPassword();

	auto local = KeyPair::Load(KeyFile("ecdh_test.priv.enc.pem"), pass);
	auto peer  = KeyPair::Load(KeyFile("ecdh_peer_test.priv.pem"));
	ASSERT_TRUE(fn_name, local);
	ASSERT_TRUE(fn_name, peer);

	auto localKp = std::make_shared<KeyPair::ECDH>(local->PublicKey(), local->PrivateKey());
	auto peerKp  = std::make_shared<KeyPair::ECDH>(peer->PublicKey(), peer->PrivateKey());
	auto peerPub = std::make_shared<KeyPair::ECDH>(peer->PublicKey(), std::nullopt);

	Secret::ECDH a(localKp, 256);
	Secret::ECDH b(peerKp, 256);
	auto s1 = a.Share(peerPub->PublicKey());
	auto s2 = b.Share(localKp->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslX25519EncryptedShare() {
	const std::string fn_name = "TestOpenSslX25519EncryptedShare";
	Password pass = TestKeysPassword();

	auto local = KeyPair::Load(KeyFile("x25519_test.priv.enc.pem"), pass);
	auto peer  = KeyPair::Load(KeyFile("x25519_peer_test.priv.pem"));
	ASSERT_TRUE(fn_name, local);
	ASSERT_TRUE(fn_name, peer);

	auto peerPub = std::make_shared<KeyPair::X25519>(peer->PublicKey(), std::nullopt);
	Secret::X25519 xLocal(local);
	Secret::X25519 xPeer(peer);
	auto s1 = xLocal.Share(peerPub->PublicKey());
	auto s2 = xPeer.Share(local->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Truncated / invalid OpenSSL private keys must not load
// ---------------------------------------------------------------------------

int TestOpenSslRsaTruncatedPrivateFails() {
	const std::string fn_name = "TestOpenSslRsaTruncatedPrivateFails";
	ASSERT_TRUE(fn_name, FileExists(KeyFile("rsa_test.priv.truncated.pem")));
	auto kp = KeyPair::Load(KeyFile("rsa_test.priv.truncated.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslDsaTruncatedPrivateFails() {
	const std::string fn_name = "TestOpenSslDsaTruncatedPrivateFails";
	ASSERT_TRUE(fn_name, FileExists(KeyFile("dsa_test.priv.truncated.pem")));
	auto kp = KeyPair::Load(KeyFile("dsa_test.priv.truncated.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEccTruncatedPrivateFails() {
	const std::string fn_name = "TestOpenSslEccTruncatedPrivateFails";
	ASSERT_TRUE(fn_name, FileExists(KeyFile("ecc_p256_test.priv.truncated.pem")));
	auto kp = KeyPair::Load(KeyFile("ecc_p256_test.priv.truncated.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdsaTruncatedPrivateFails() {
	const std::string fn_name = "TestOpenSslEcdsaTruncatedPrivateFails";
	ASSERT_TRUE(fn_name, FileExists(KeyFile("ecdsa_test.priv.truncated.pem")));
	auto kp = KeyPair::Load(KeyFile("ecdsa_test.priv.truncated.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdhTruncatedPrivateFails() {
	const std::string fn_name = "TestOpenSslEcdhTruncatedPrivateFails";
	ASSERT_TRUE(fn_name, FileExists(KeyFile("ecdh_test.priv.truncated.pem")));
	auto kp = KeyPair::Load(KeyFile("ecdh_test.priv.truncated.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEd25519TruncatedPrivateFails() {
	const std::string fn_name = "TestOpenSslEd25519TruncatedPrivateFails";
	ASSERT_TRUE(fn_name, FileExists(KeyFile("ed25519_test.priv.truncated.pem")));
	auto kp = KeyPair::Load(KeyFile("ed25519_test.priv.truncated.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslX25519TruncatedPrivateFails() {
	const std::string fn_name = "TestOpenSslX25519TruncatedPrivateFails";
	ASSERT_TRUE(fn_name, FileExists(KeyFile("x25519_test.priv.truncated.pem")));
	auto kp = KeyPair::Load(KeyFile("x25519_test.priv.truncated.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// OpenSSL edge cases
// ---------------------------------------------------------------------------

int TestOpenSslEdgeMismatchedPubPrivFail() {
	const std::string fn_name = "TestOpenSslEdgeMismatchedPubPrivFail";
	auto kp = KeyPair::Load(KeyFile("rsa_test.pub.pem"), KeyFile("dsa_test.priv.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEdgePublicOnlyUsable() {
	const std::string fn_name = "TestOpenSslEdgePublicOnlyUsable";
	auto pubOnly = KeyPair::Load(KeyFile("rsa_test.pub.pem"));
	ASSERT_TRUE(fn_name, pubOnly);
	ASSERT_FALSE(fn_name, pubOnly->HasPrivateKey());

	auto full = KeyPair::Load(KeyFile("rsa_test.pub.pem"), KeyFile("rsa_test.priv.pem"));
	ASSERT_TRUE(fn_name, full && full->HasPrivateKey());

	Crypter::RSA encryptor(pubOnly);
	Crypter::RSA decryptor(full);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, encryptor.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, decryptor.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEdgeConcatenatedPemRoundTrip() {
	const std::string fn_name = "TestOpenSslEdgeConcatenatedPemRoundTrip";
	const std::string priv = ReadAllText(KeyFile("rsa_test.priv.pem"));
	const std::string pub = ReadAllText(KeyFile("rsa_test.pub.pem"));
	ASSERT_FALSE(fn_name, priv.empty() || pub.empty());

	const fs::path combined = KeysDir() / "rsa_test.combined.pem";
	ASSERT_TRUE(fn_name, WriteText(combined, priv + pub));

	auto kp = KeyPair::Load(combined);
	ASSERT_TRUE(fn_name, kp);
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());

	Crypter::RSA cipher(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, cipher.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, cipher.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEdgeTruncatedEncryptedPrivateFails() {
	const std::string fn_name = "TestOpenSslEdgeTruncatedEncryptedPrivateFails";
	auto bytes = ReadAllBytes(KeyFile("rsa_test.priv.enc.pem"));
	ASSERT_FALSE(fn_name, bytes.empty());
	bytes.resize(std::max<size_t>(1, bytes.size() / 2));

	const fs::path truncated = KeysDir() / "rsa_test.priv.enc.truncated.pem";
	ASSERT_TRUE(fn_name, WriteBytes(truncated, bytes));

	ASSERT_FALSE(fn_name, KeyPair::Load(truncated, TestKeysPassword()));
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEdgeEmptyPasswordOnEncryptedFails() {
	const std::string fn_name = "TestOpenSslEdgeEmptyPasswordOnEncryptedFails";
	ASSERT_FALSE(fn_name, KeyPair::Load(KeyFile("rsa_test.priv.enc.pem"), Password("")));
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEdgePasswordOnPlainPrivateStillLoads() {
	const std::string fn_name = "TestOpenSslEdgePasswordOnPlainPrivateStillLoads";
	auto kp = KeyPair::Load(KeyFile("rsa_test.priv.pem"), TestKeysPassword());
	ASSERT_TRUE(fn_name, kp);
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());

	Crypter::RSA cipher(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, cipher.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, cipher.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEdgeSwappedPathsFail() {
	const std::string fn_name = "TestOpenSslEdgeSwappedPathsFail";
	auto kp = KeyPair::Load(KeyFile("rsa_test.priv.pem"), KeyFile("rsa_test.pub.pem"));
	ASSERT_FALSE(fn_name, kp);
	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEdgeLoadThenLibrarySaveReload() {
	const std::string fn_name = "TestOpenSslEdgeLoadThenLibrarySaveReload";
	auto original = KeyPair::Load(KeyFile("rsa_test.pub.pem"), KeyFile("rsa_test.priv.pem"));
	ASSERT_TRUE(fn_name, original);

	const fs::path outDir = KeysDir() / "edge_resave";
	fs::create_directories(outDir);
	ASSERT_TRUE(fn_name, original->Save(outDir, "rsa_resave", KeyPair::StorageFormat::PEM));

	auto reloaded = KeyPair::Load(outDir / "rsa_resave.pub.pem", outDir / "rsa_resave.pem");
	ASSERT_TRUE(fn_name, reloaded);

	Crypter::RSA cipher(reloaded);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, cipher.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, cipher.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// PKCS#1 / traditional private key Load (explicit OpenSSL fixtures)
//
// rsa_test.priv.pkcs1.der / .pem are forced with `openssl rsa` (RSAPrivateKey).
// ecc_* / ecdsa_* / ecdh_*.priv.sec1.* are SEC1 traditional EC (not PKCS#1).
// These must not overwrite the default *.priv.der paths used by other tests.
// ---------------------------------------------------------------------------

int TestOpenSslRsaPkcs1DerEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslRsaPkcs1DerEncryptDecrypt";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "rsa_test.pub.der", "rsa_test.priv.pkcs1.der", kp, KeyPair::Type::RSA) != 0)
		return 1;

	Crypter::RSA crypter(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaPkcs1PemEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslRsaPkcs1PemEncryptDecrypt";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "rsa_test.pub.pem", "rsa_test.priv.pkcs1.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;

	Crypter::RSA crypter(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslRsaPkcs1DerSignVerify() {
	const std::string fn_name = "TestOpenSslRsaPkcs1DerSignVerify";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "rsa_test.pub.der", "rsa_test.priv.pkcs1.der", kp, KeyPair::Type::RSA) != 0)
		return 1;

	Signer::RSA signer(kp);
	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	ASSERT_TRUE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		std::string(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size())
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEccSec1DerEncryptDecrypt() {
	const std::string fn_name = "TestOpenSslEccSec1DerEncryptDecrypt";
	KeyPair::Generic::PointerType kp;
	// SEC1 traditional EC private; type may be ECC (or EC family) depending on detector
	if (AssertLoadPair(fn_name, "ecc_p256_test.pub.der", "ecc_p256_test.priv.sec1.der", kp, KeyPair::Type::ECC, false) != 0)
		return 1;
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());

	Crypter::ECC crypter(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Hybrid
	));
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdsaSec1DerSignVerify() {
	const std::string fn_name = "TestOpenSslEcdsaSec1DerSignVerify";
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair(fn_name, "ecdsa_test.pub.der", "ecdsa_test.priv.sec1.der", kp, KeyPair::Type::ECDSA, false) != 0)
		return 1;

	Signer::ECDSA signer(kp);
	FIFO signature;
	ASSERT_TRUE(fn_name, signer.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		signature
	));
	ASSERT_TRUE(fn_name, signer.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		std::string(reinterpret_cast<const char*>(signature.Data().data()), signature.Data().size())
	));

	RETURN_TEST(fn_name, 0);
}

int TestOpenSslEcdhSec1DerShare() {
	const std::string fn_name = "TestOpenSslEcdhSec1DerShare";
	KeyPair::Generic::PointerType local;
	if (AssertLoadPair(fn_name, "ecdh_test.pub.der", "ecdh_test.priv.sec1.der", local, KeyPair::Type::ECDH, false) != 0)
		return 1;

	auto peer = KeyPair::Load(KeyFile("ecdh_peer_test.pub.der"));
	ASSERT_TRUE(fn_name, peer);

	Secret::ECDH a(local);
	Secret::ECDH b(peer);
	// Peer has public only for Share from local; for mutual share load peer with priv if available
	auto peerFull = KeyPair::Load(KeyFile("ecdh_peer_test.pub.der"), KeyFile("ecdh_peer_test.priv.der"));
	ASSERT_TRUE(fn_name, peerFull);

	Secret::ECDH peerSide(peerFull);
	auto s1 = a.Share(peerFull->PublicKey());
	auto s2 = peerSide.Share(local->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestOpenSslRsaEncryptDecrypt();
	result += TestOpenSslRsaHybridEncryptDecrypt();
	result += TestOpenSslRsaSignVerify();
	result += TestOpenSslRsaDerRoundTripUse();
	result += TestOpenSslRsaPrivateOnlyThenEncrypt();

	result += TestOpenSslDsaSignVerify();
	result += TestOpenSslEcdsaSignVerify();
	result += TestOpenSslEccEncryptDecrypt();

	result += TestOpenSslEd25519SignVerify();
	result += TestOpenSslEd25519DerSignVerify();

	result += TestOpenSslEcdhShare();
	result += TestOpenSslX25519Share();

	result += TestLibraryRsaSaveLoadStillEncrypts();
	result += TestOpenSslEncryptedPrivateWithoutPasswordFails();

	result += TestOpenSslRsaPrivateOnlyDerivesPublic();
	result += TestOpenSslDsaPrivateOnlyDerivesPublic();
	result += TestOpenSslEcdsaPrivateOnlyDerivesPublic();
	result += TestOpenSslEccPrivateOnlyDerivesPublic();
	result += TestOpenSslEd25519PrivateOnlyDerivesPublic();
	result += TestOpenSslEcdhPrivateOnlyDerivesPublic();
	result += TestOpenSslX25519PrivateOnlyDerivesPublic();

	result += TestOpenSslRsaEncryptedLoadEncryptDecrypt();
	result += TestOpenSslRsaEncryptedLoadPrivateOnly();
	result += TestOpenSslRsaEncryptedWrongPasswordFails();
	result += TestOpenSslRsaEncryptedSignVerify();
	result += TestOpenSslDsaEncryptedSignVerify();
	result += TestOpenSslEcdsaEncryptedSignVerify();
	result += TestOpenSslEccEncryptedEncryptDecrypt();
	result += TestOpenSslEd25519EncryptedSignVerify();
	result += TestOpenSslEcdhEncryptedShare();
	result += TestOpenSslX25519EncryptedShare();

	result += TestOpenSslRsaTruncatedPrivateFails();
	result += TestOpenSslDsaTruncatedPrivateFails();
	result += TestOpenSslEccTruncatedPrivateFails();
	result += TestOpenSslEcdsaTruncatedPrivateFails();
	result += TestOpenSslEcdhTruncatedPrivateFails();
	result += TestOpenSslEd25519TruncatedPrivateFails();
	result += TestOpenSslX25519TruncatedPrivateFails();

	result += TestOpenSslEdgeMismatchedPubPrivFail();
	result += TestOpenSslEdgePublicOnlyUsable();
	result += TestOpenSslEdgeConcatenatedPemRoundTrip();
	result += TestOpenSslEdgeTruncatedEncryptedPrivateFails();
	result += TestOpenSslEdgeEmptyPasswordOnEncryptedFails();
	result += TestOpenSslEdgePasswordOnPlainPrivateStillLoads();
	result += TestOpenSslEdgeSwappedPathsFail();
	result += TestOpenSslEdgeLoadThenLibrarySaveReload();

	result += TestOpenSslRsaPkcs1DerEncryptDecrypt();
	result += TestOpenSslRsaPkcs1PemEncryptDecrypt();
	result += TestOpenSslRsaPkcs1DerSignVerify();
	result += TestOpenSslEccSec1DerEncryptDecrypt();
	result += TestOpenSslEcdsaSec1DerSignVerify();
	result += TestOpenSslEcdhSec1DerShare();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
