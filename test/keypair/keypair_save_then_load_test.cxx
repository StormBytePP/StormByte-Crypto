#include <StormByte/buffer/fifo.hxx>
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
#include <StormByte/test_handlers.h>

#include <filesystem>
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

	fs::path SaveDir() {
		return KeysDir() / "save_roundtrip";
	}

	bool FileExists(const fs::path& p) {
		return fs::exists(p) && fs::is_regular_file(p);
	}

	const std::string kPlainText = "StormByte Save/Load round-trip payload";

	// Generated once per process (expensive)
	KeyPair::Generic::PointerType g_rsa;
	KeyPair::Generic::PointerType g_dsa;
	KeyPair::Generic::PointerType g_ecc;
	KeyPair::Generic::PointerType g_ecdsa;
	KeyPair::Generic::PointerType g_ecdh_a;
	KeyPair::Generic::PointerType g_ecdh_b;
	KeyPair::Generic::PointerType g_ed25519;
	KeyPair::Generic::PointerType g_x25519_a;
	KeyPair::Generic::PointerType g_x25519_b;

	int GenerateAllKeypairs(const std::string& fn_name) {
		g_rsa = KeyPair::RSA::Generate(2048);
		ASSERT_TRUE(fn_name, g_rsa);

		g_dsa = KeyPair::DSA::Generate(2048);
		ASSERT_TRUE(fn_name, g_dsa);

		g_ecc = KeyPair::ECC::Generate(256);
		ASSERT_TRUE(fn_name, g_ecc);

		g_ecdsa = KeyPair::ECDSA::Generate(256);
		ASSERT_TRUE(fn_name, g_ecdsa);

		g_ecdh_a = KeyPair::ECDH::Generate(256);
		g_ecdh_b = KeyPair::ECDH::Generate(256);
		ASSERT_TRUE(fn_name, g_ecdh_a);
		ASSERT_TRUE(fn_name, g_ecdh_b);

		g_ed25519 = KeyPair::ED25519::Generate();
		ASSERT_TRUE(fn_name, g_ed25519);

		g_x25519_a = KeyPair::X25519::Generate();
		g_x25519_b = KeyPair::X25519::Generate();
		ASSERT_TRUE(fn_name, g_x25519_a);
		ASSERT_TRUE(fn_name, g_x25519_b);

		return 0;
	}

	int SaveAllKeypairs(const std::string& fn_name) {
		const fs::path out = SaveDir();
		std::error_code ec;
		fs::remove_all(out, ec);
		fs::create_directories(out, ec);
		ASSERT_TRUE(fn_name, fs::is_directory(out));

		ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_dsa->Save(out, "dsa", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_ecc->Save(out, "ecc", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_ecdsa->Save(out, "ecdsa", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_ecdh_a->Save(out, "ecdh_a", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_ecdh_b->Save(out, "ecdh_b", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_ed25519->Save(out, "ed25519", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_x25519_a->Save(out, "x25519_a", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(fn_name, g_x25519_b->Save(out, "x25519_b", KeyPair::StorageFormat::PEM));

		// DER variants (subset)
		ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa_der", KeyPair::StorageFormat::DER));
		ASSERT_TRUE(fn_name, g_ed25519->Save(out, "ed25519_der", KeyPair::StorageFormat::DER));

		ASSERT_TRUE(fn_name, FileExists(out / "rsa.pub.pem"));
		ASSERT_TRUE(fn_name, FileExists(out / "rsa.pem"));
		ASSERT_TRUE(fn_name, FileExists(out / "rsa_der.pub.der"));
		ASSERT_TRUE(fn_name, FileExists(out / "rsa_der.der"));

		return 0;
	}

	Password TestKeysPassword() {
		return Password(STORMBYTE_TEST_KEYS_PASSWORD);
	}
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

int TestSaveLoadRsaEncryptDecrypt() {
	const std::string fn_name = "TestSaveLoadRsaEncryptDecrypt";
	const fs::path out = SaveDir();

	auto loaded = KeyPair::Load(out / "rsa.pub.pem", out / "rsa.pem");
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_TRUE(fn_name, loaded->HasPrivateKey());
	ASSERT_EQUAL(fn_name, loaded->PublicKey(), g_rsa->PublicKey());

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

int TestSaveLoadRsaHybridEncryptDecrypt() {
	const std::string fn_name = "TestSaveLoadRsaHybridEncryptDecrypt";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "rsa.pub.pem", out / "rsa.pem");
	ASSERT_TRUE(fn_name, loaded);

	const std::string longText = kPlainText + std::string(4096, 'B');
	Crypter::RSA crypter(loaded);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(fn_name, crypter.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(longText.data()), longText.size()),
		encrypted,
		Crypter::Asymmetric::Strategy::Hybrid
	));
	ASSERT_TRUE(fn_name, crypter.Decrypt(
		std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
		decrypted
	));
	const std::string recovered(reinterpret_cast<const char*>(decrypted.Data().data()), decrypted.Data().size());
	ASSERT_EQUAL(fn_name, recovered, longText);

	RETURN_TEST(fn_name, 0);
}

int TestSaveLoadRsaSignVerify() {
	const std::string fn_name = "TestSaveLoadRsaSignVerify";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "rsa.pub.pem", out / "rsa.pem");
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::RSA>(loaded->PublicKey(), std::nullopt);
	Signer::RSA signer(loaded);
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

int TestSaveLoadRsaDerEncryptDecrypt() {
	const std::string fn_name = "TestSaveLoadRsaDerEncryptDecrypt";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "rsa_der.pub.der", out / "rsa_der.der");
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

int TestSaveLoadRsaPrivateOnly() {
	const std::string fn_name = "TestSaveLoadRsaPrivateOnly";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "rsa.pem");
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_TRUE(fn_name, loaded->HasPrivateKey());
	ASSERT_TRUE(fn_name, !loaded->PublicKey().empty());

	auto pubOnly = std::make_shared<KeyPair::RSA>(loaded->PublicKey(), std::nullopt);
	Crypter::RSA encryptor(pubOnly);
	Crypter::RSA decryptor(loaded);
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

// ---------------------------------------------------------------------------
// DSA / ECDSA / Ed25519
// ---------------------------------------------------------------------------

int TestSaveLoadDsaSignVerify() {
	const std::string fn_name = "TestSaveLoadDsaSignVerify";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "dsa.pub.pem", out / "dsa.pem");
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_EQUAL(fn_name, loaded->PublicKey(), g_dsa->PublicKey());

	auto pubOnly = std::make_shared<KeyPair::DSA>(loaded->PublicKey(), std::nullopt);
	Signer::DSA signer(loaded);
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

int TestSaveLoadEcdsaSignVerify() {
	const std::string fn_name = "TestSaveLoadEcdsaSignVerify";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "ecdsa.pub.pem", out / "ecdsa.pem");
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::ECDSA>(loaded->PublicKey(), std::nullopt);
	Signer::ECDSA signer(loaded);
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

int TestSaveLoadEd25519SignVerify() {
	const std::string fn_name = "TestSaveLoadEd25519SignVerify";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "ed25519.pub.pem", out / "ed25519.pem");
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_EQUAL(fn_name, loaded->PublicKey(), g_ed25519->PublicKey());

	auto pubOnly = std::make_shared<KeyPair::ED25519>(loaded->PublicKey(), std::nullopt);
	Signer::ED25519 signer(loaded);
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

int TestSaveLoadEd25519DerSignVerify() {
	const std::string fn_name = "TestSaveLoadEd25519DerSignVerify";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "ed25519_der.pub.der", out / "ed25519_der.der");
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::ED25519>(loaded->PublicKey(), std::nullopt);
	Signer::ED25519 signer(loaded);
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

// ---------------------------------------------------------------------------
// ECC
// ---------------------------------------------------------------------------

int TestSaveLoadEccEncryptDecrypt() {
	const std::string fn_name = "TestSaveLoadEccEncryptDecrypt";
	const fs::path out = SaveDir();
	auto loaded = KeyPair::Load(out / "ecc.pub.pem", out / "ecc.pem");
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::ECC>(loaded->PublicKey(), std::nullopt);
	Crypter::ECC encryptor(pubOnly);
	Crypter::ECC decryptor(loaded);
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

// ---------------------------------------------------------------------------
// ECDH / X25519
// ---------------------------------------------------------------------------

int TestSaveLoadEcdhShare() {
	const std::string fn_name = "TestSaveLoadEcdhShare";
	const fs::path out = SaveDir();

	auto a = KeyPair::Load(out / "ecdh_a.pub.pem", out / "ecdh_a.pem");
	auto b = KeyPair::Load(out / "ecdh_b.pub.pem", out / "ecdh_b.pem");
	std::cerr << "a=" << (a ? "ok" : "null") << " b=" << (b ? "ok" : "null") << "\n";
	std::cerr << "ecdh_a.pem exists=" << fs::exists(out / "ecdh_a.pem")
	<< " size=" << (fs::exists(out / "ecdh_a.pem") ? fs::file_size(out / "ecdh_a.pem") : 0)
	<< std::endl;
	ASSERT_TRUE(fn_name, a);
	ASSERT_TRUE(fn_name, b);

	auto ecdhA = std::make_shared<KeyPair::ECDH>(a->PublicKey(), a->PrivateKey());
	auto ecdhB = std::make_shared<KeyPair::ECDH>(b->PublicKey(), b->PrivateKey());

	Secret::ECDH sa(ecdhA, 256);
	Secret::ECDH sb(ecdhB, 256);
	auto s1 = sa.Share(ecdhB->PublicKey());
	auto s2 = sb.Share(ecdhA->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int TestSaveLoadX25519Share() {
	const std::string fn_name = "TestSaveLoadX25519Share";
	const fs::path out = SaveDir();

	auto a = KeyPair::Load(out / "x25519_a.pub.pem", out / "x25519_a.pem");
	auto b = KeyPair::Load(out / "x25519_b.pub.pem", out / "x25519_b.pem");
	ASSERT_TRUE(fn_name, a);
	ASSERT_TRUE(fn_name, b);

	Secret::X25519 sa(a);
	Secret::X25519 sb(b);
	auto s1 = sa.Share(b->PublicKey());
	auto s2 = sb.Share(a->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// SavePublic / SavePrivate helpers
// ---------------------------------------------------------------------------

int TestSavePublicOnlyThenLoad() {
	const std::string fn_name = "TestSavePublicOnlyThenLoad";
	const fs::path out = SaveDir();
	const auto pubPath = out / "rsa_public_only.pem";

	ASSERT_TRUE(fn_name, g_rsa->SavePublic(pubPath, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, FileExists(pubPath));

	auto loaded = KeyPair::Load(pubPath);
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_FALSE(fn_name, loaded->HasPrivateKey());
	ASSERT_EQUAL(fn_name, loaded->PublicKey(), g_rsa->PublicKey());

	Crypter::RSA encryptor(loaded);
	Crypter::RSA decryptor(g_rsa);
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

int TestSavePrivateOnlyThenLoad() {
	const std::string fn_name = "TestSavePrivateOnlyThenLoad";
	const fs::path out = SaveDir();
	const auto privPath = out / "rsa_private_only.pem";

	ASSERT_TRUE(fn_name, g_rsa->SavePrivate(privPath, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, FileExists(privPath));

	auto loaded = KeyPair::Load(privPath);
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_TRUE(fn_name, loaded->HasPrivateKey());
	ASSERT_TRUE(fn_name, !loaded->PublicKey().empty());

	auto pubOnly = std::make_shared<KeyPair::RSA>(loaded->PublicKey(), std::nullopt);
	Crypter::RSA encryptor(pubOnly);
	Crypter::RSA decryptor(loaded);
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

// ---------------------------------------------------------------------------
// Encrypted Save → Load (requires Save* with Password)
// ---------------------------------------------------------------------------

int TestSaveEncryptedRsaPrivateLoadDecrypt() {
	const std::string fn_name = "TestSaveEncryptedRsaPrivateLoadDecrypt";
	const fs::path out = SaveDir();
	const auto encPath = out / "rsa_priv_enc.pem";
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_rsa->SavePrivate(encPath, pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, FileExists(encPath));
	ASSERT_FALSE(fn_name, KeyPair::Load(encPath));

	auto loaded = KeyPair::Load(encPath, pass);
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_TRUE(fn_name, loaded->HasPrivateKey());
	ASSERT_TRUE(fn_name, !loaded->PublicKey().empty());

	auto pubOnly = std::make_shared<KeyPair::RSA>(loaded->PublicKey(), std::nullopt);
	Crypter::RSA encryptor(pubOnly);
	Crypter::RSA decryptor(loaded);

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

int TestSaveEncryptedRsaPairLoadSignVerify() {
	const std::string fn_name = "TestSaveEncryptedRsaPairLoadSignVerify";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa_enc_pair", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, FileExists(out / "rsa_enc_pair.pub.pem"));
	ASSERT_TRUE(fn_name, FileExists(out / "rsa_enc_pair.pem"));
	ASSERT_FALSE(fn_name, KeyPair::Load(out / "rsa_enc_pair.pub.pem", out / "rsa_enc_pair.pem"));

	auto loaded = KeyPair::Load(out / "rsa_enc_pair.pub.pem", out / "rsa_enc_pair.pem", pass);
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::RSA>(loaded->PublicKey(), std::nullopt);
	Signer::RSA signer(loaded);
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

int TestSaveEncryptedWrongPasswordFails() {
	const std::string fn_name = "TestSaveEncryptedWrongPasswordFails";
	const fs::path out = SaveDir();
	const auto encPath = out / "rsa_priv_enc_wrong.pem";
	Password pass = TestKeysPassword();
	Password wrong("DefinitelyNotTheRightPassphrase!");

	ASSERT_TRUE(fn_name, g_rsa->SavePrivate(encPath, pass, KeyPair::StorageFormat::PEM));
	ASSERT_FALSE(fn_name, KeyPair::Load(encPath, wrong));
	ASSERT_TRUE(fn_name, KeyPair::Load(encPath, pass));

	RETURN_TEST(fn_name, 0);
}

int TestSaveEncryptedDifferentPasswordsIndependent() {
	const std::string fn_name = "TestSaveEncryptedDifferentPasswordsIndependent";
	const fs::path out = SaveDir();
	Password passA = TestKeysPassword();
	Password passB("StormByteAltTestPassphrase!");

	const auto pathA = out / "rsa_enc_A.pem";
	const auto pathB = out / "rsa_enc_B.pem";

	ASSERT_TRUE(fn_name, g_rsa->SavePrivate(pathA, passA, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_rsa->SavePrivate(pathB, passB, KeyPair::StorageFormat::PEM));

	ASSERT_TRUE(fn_name, KeyPair::Load(pathA, passA));
	ASSERT_TRUE(fn_name, KeyPair::Load(pathB, passB));
	ASSERT_FALSE(fn_name, KeyPair::Load(pathA, passB));
	ASSERT_FALSE(fn_name, KeyPair::Load(pathB, passA));

	auto kpA = KeyPair::Load(pathA, passA);
	auto kpB = KeyPair::Load(pathB, passB);
	ASSERT_TRUE(fn_name, kpA && kpB);
	ASSERT_EQUAL(fn_name, kpA->PublicKey(), g_rsa->PublicKey());
	ASSERT_EQUAL(fn_name, kpB->PublicKey(), g_rsa->PublicKey());

	RETURN_TEST(fn_name, 0);
}

int TestSaveEncryptedEd25519SignVerify() {
	const std::string fn_name = "TestSaveEncryptedEd25519SignVerify";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_ed25519->SavePrivate(out / "ed25519_enc.pem", pass, KeyPair::StorageFormat::PEM));
	auto loaded = KeyPair::Load(out / "ed25519_enc.pem", pass);
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::ED25519>(loaded->PublicKey(), std::nullopt);
	Signer::ED25519 signer(loaded);
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

int TestSaveEncryptedDsaSignVerify() {
	const std::string fn_name = "TestSaveEncryptedDsaSignVerify";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_dsa->SavePrivate(out / "dsa_enc.pem", pass, KeyPair::StorageFormat::PEM));
	auto loaded = KeyPair::Load(out / "dsa_enc.pem", pass);
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::DSA>(loaded->PublicKey(), std::nullopt);
	Signer::DSA signer(loaded);
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

int TestSaveEncryptedEccEncryptDecrypt() {
	const std::string fn_name = "TestSaveEncryptedEccEncryptDecrypt";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_ecc->SavePrivate(out / "ecc_enc.pem", pass, KeyPair::StorageFormat::PEM));
	auto loaded = KeyPair::Load(out / "ecc_enc.pem", pass);
	ASSERT_TRUE(fn_name, loaded);

	auto pubOnly = std::make_shared<KeyPair::ECC>(loaded->PublicKey(), std::nullopt);
	Crypter::ECC encryptor(pubOnly);
	Crypter::ECC decryptor(loaded);

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

int TestSaveEncryptedX25519Share() {
	const std::string fn_name = "TestSaveEncryptedX25519Share";
	const fs::path out = SaveDir();
	Password passA = TestKeysPassword();
	Password passB("StormByteAltTestPassphrase!");

	ASSERT_TRUE(fn_name, g_x25519_a->SavePrivate(out / "x25519_a_enc.pem", passA, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_x25519_b->SavePrivate(out / "x25519_b_enc.pem", passB, KeyPair::StorageFormat::PEM));

	auto a = KeyPair::Load(out / "x25519_a_enc.pem", passA);
	auto b = KeyPair::Load(out / "x25519_b_enc.pem", passB);
	ASSERT_TRUE(fn_name, a && b);

	Secret::X25519 sa(a);
	Secret::X25519 sb(b);
	auto s1 = sa.Share(b->PublicKey());
	auto s2 = sb.Share(a->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int TestSaveEncryptedPublicStaysPlain() {
	const std::string fn_name = "TestSaveEncryptedPublicStaysPlain";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa_enc_pubcheck", pass, KeyPair::StorageFormat::PEM));

	auto pubOnly = KeyPair::Load(out / "rsa_enc_pubcheck.pub.pem");
	ASSERT_TRUE(fn_name, pubOnly);
	ASSERT_FALSE(fn_name, pubOnly->HasPrivateKey());
	ASSERT_EQUAL(fn_name, pubOnly->PublicKey(), g_rsa->PublicKey());

	RETURN_TEST(fn_name, 0);
}

// ---------------------------------------------------------------------------
// Cross-format PEM ↔ DER (plain and encrypted): same key material
// ---------------------------------------------------------------------------

int TestCrossFormatRsaPemEncryptDerDecrypt() {
	const std::string fn_name = "TestCrossFormatRsaPemEncryptDerDecrypt";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa_cross_der", KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "rsa_cross_pem.pub.pem", out / "rsa_cross_pem.pem");
	auto derKp = KeyPair::Load(out / "rsa_cross_der.pub.der", out / "rsa_cross_der.der");
	ASSERT_TRUE(fn_name, pemKp && derKp);

	Crypter::RSA encryptor(pemKp);
	Crypter::RSA decryptor(derKp);

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

	// Reverse direction: DER encrypt → PEM decrypt
	FIFO encrypted2, decrypted2;
	Crypter::RSA encryptor2(derKp);
	Crypter::RSA decryptor2(pemKp);
	ASSERT_TRUE(fn_name, encryptor2.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(kPlainText.data()), kPlainText.size()),
		encrypted2,
		Crypter::Asymmetric::Strategy::Native
	));
	ASSERT_TRUE(fn_name, decryptor2.Decrypt(
		std::span<const std::byte>(encrypted2.Data().data(), encrypted2.Data().size()),
		decrypted2
	));
	const std::string recovered2(reinterpret_cast<const char*>(decrypted2.Data().data()), decrypted2.Data().size());
	ASSERT_EQUAL(fn_name, recovered2, kPlainText);

	RETURN_TEST(fn_name, 0);
}

int TestCrossFormatRsaEncryptedPemDer() {
	const std::string fn_name = "TestCrossFormatRsaEncryptedPemDer";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_rsa->SavePrivate(out / "rsa_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_rsa->SavePrivate(out / "rsa_enc_cross.der", pass, KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "rsa_enc_cross.pem", pass);
	auto derKp = KeyPair::Load(out / "rsa_enc_cross.der", pass);
	ASSERT_TRUE(fn_name, pemKp && derKp);

	auto pubPem = std::make_shared<KeyPair::RSA>(pemKp->PublicKey(), std::nullopt);
	Crypter::RSA encryptor(pubPem);
	Crypter::RSA decryptor(derKp);

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

int TestCrossFormatRsaPemSignDerVerify() {
	const std::string fn_name = "TestCrossFormatRsaPemSignDerVerify";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa_sig_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_rsa->Save(out, "rsa_sig_der", KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "rsa_sig_pem.pub.pem", out / "rsa_sig_pem.pem");
	auto derKp = KeyPair::Load(out / "rsa_sig_der.pub.der", out / "rsa_sig_der.der");
	ASSERT_TRUE(fn_name, pemKp && derKp);

	Signer::RSA signer(pemKp);
	auto derPub = std::make_shared<KeyPair::RSA>(derKp->PublicKey(), std::nullopt);
	Signer::RSA verifier(derPub);

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

int TestCrossFormatDsaPemSignDerVerify() {
	const std::string fn_name = "TestCrossFormatDsaPemSignDerVerify";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_dsa->Save(out, "dsa_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_dsa->Save(out, "dsa_cross_der", KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "dsa_cross_pem.pub.pem", out / "dsa_cross_pem.pem");
	auto derKp = KeyPair::Load(out / "dsa_cross_der.pub.der", out / "dsa_cross_der.der");
	ASSERT_TRUE(fn_name, pemKp && derKp);

	Signer::DSA signer(pemKp);
	auto derPub = std::make_shared<KeyPair::DSA>(derKp->PublicKey(), std::nullopt);
	Signer::DSA verifier(derPub);

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

int TestCrossFormatEcdsaPemSignDerVerify() {
	const std::string fn_name = "TestCrossFormatEcdsaPemSignDerVerify";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_ecdsa->Save(out, "ecdsa_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_ecdsa->Save(out, "ecdsa_cross_der", KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "ecdsa_cross_pem.pub.pem", out / "ecdsa_cross_pem.pem");
	auto derKp = KeyPair::Load(out / "ecdsa_cross_der.pub.der", out / "ecdsa_cross_der.der");
	ASSERT_TRUE(fn_name, pemKp && derKp);

	Signer::ECDSA signer(pemKp);
	auto derPub = std::make_shared<KeyPair::ECDSA>(derKp->PublicKey(), std::nullopt);
	Signer::ECDSA verifier(derPub);

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

int TestCrossFormatEd25519PemSignDerVerify() {
	const std::string fn_name = "TestCrossFormatEd25519PemSignDerVerify";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_ed25519->Save(out, "ed25519_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_ed25519->Save(out, "ed25519_cross_der", KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "ed25519_cross_pem.pub.pem", out / "ed25519_cross_pem.pem");
	auto derKp = KeyPair::Load(out / "ed25519_cross_der.pub.der", out / "ed25519_cross_der.der");
	ASSERT_TRUE(fn_name, pemKp && derKp);

	Signer::ED25519 signer(pemKp);
	auto derPub = std::make_shared<KeyPair::ED25519>(derKp->PublicKey(), std::nullopt);
	Signer::ED25519 verifier(derPub);

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

int TestCrossFormatEd25519EncryptedPemDer() {
	const std::string fn_name = "TestCrossFormatEd25519EncryptedPemDer";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_ed25519->SavePrivate(out / "ed25519_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_ed25519->SavePrivate(out / "ed25519_enc_cross.der", pass, KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "ed25519_enc_cross.pem", pass);
	auto derKp = KeyPair::Load(out / "ed25519_enc_cross.der", pass);
	ASSERT_TRUE(fn_name, pemKp && derKp);

	Signer::ED25519 signer(pemKp);
	auto derPub = std::make_shared<KeyPair::ED25519>(derKp->PublicKey(), std::nullopt);
	Signer::ED25519 verifier(derPub);

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

int TestCrossFormatEccPemEncryptDerDecrypt() {
	const std::string fn_name = "TestCrossFormatEccPemEncryptDerDecrypt";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_ecc->Save(out, "ecc_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_ecc->Save(out, "ecc_cross_der", KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "ecc_cross_pem.pub.pem", out / "ecc_cross_pem.pem");
	auto derKp = KeyPair::Load(out / "ecc_cross_der.pub.der", out / "ecc_cross_der.der");
	ASSERT_TRUE(fn_name, pemKp && derKp);

	auto pemPub = std::make_shared<KeyPair::ECC>(pemKp->PublicKey(), std::nullopt);
	Crypter::ECC encryptor(pemPub);
	Crypter::ECC decryptor(derKp);

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

int TestCrossFormatEcdhPemDerShare() {
	const std::string fn_name = "TestCrossFormatEcdhPemDerShare";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_ecdh_a->Save(out, "ecdh_a_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_ecdh_a->Save(out, "ecdh_a_cross_der", KeyPair::StorageFormat::DER));
	ASSERT_TRUE(fn_name, g_ecdh_b->Save(out, "ecdh_b_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_ecdh_b->Save(out, "ecdh_b_cross_der", KeyPair::StorageFormat::DER));

	auto aPem = KeyPair::Load(out / "ecdh_a_cross_pem.pub.pem", out / "ecdh_a_cross_pem.pem");
	auto bDer = KeyPair::Load(out / "ecdh_b_cross_der.pub.der", out / "ecdh_b_cross_der.der");
	ASSERT_TRUE(fn_name, aPem && bDer);

	auto ecdhA = std::make_shared<KeyPair::ECDH>(aPem->PublicKey(), aPem->PrivateKey());
	auto ecdhB = std::make_shared<KeyPair::ECDH>(bDer->PublicKey(), bDer->PrivateKey());

	Secret::ECDH sa(ecdhA, 256);
	Secret::ECDH sb(ecdhB, 256);
	auto s1 = sa.Share(ecdhB->PublicKey());
	auto s2 = sb.Share(ecdhA->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int TestCrossFormatX25519PemDerShare() {
	const std::string fn_name = "TestCrossFormatX25519PemDerShare";
	const fs::path out = SaveDir();

	ASSERT_TRUE(fn_name, g_x25519_a->Save(out, "x25519_a_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_x25519_a->Save(out, "x25519_a_cross_der", KeyPair::StorageFormat::DER));
	ASSERT_TRUE(fn_name, g_x25519_b->Save(out, "x25519_b_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_x25519_b->Save(out, "x25519_b_cross_der", KeyPair::StorageFormat::DER));

	auto aPem = KeyPair::Load(out / "x25519_a_cross_pem.pub.pem", out / "x25519_a_cross_pem.pem");
	auto bDer = KeyPair::Load(out / "x25519_b_cross_der.pub.der", out / "x25519_b_cross_der.der");
	ASSERT_TRUE(fn_name, aPem && bDer);

	Secret::X25519 sa(aPem);
	Secret::X25519 sb(bDer);
	auto s1 = sa.Share(bDer->PublicKey());
	auto s2 = sb.Share(aPem->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int TestCrossFormatX25519EncryptedPemDerShare() {
	const std::string fn_name = "TestCrossFormatX25519EncryptedPemDerShare";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_x25519_a->SavePrivate(out / "x25519_a_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_x25519_b->SavePrivate(out / "x25519_b_enc_cross.der", pass, KeyPair::StorageFormat::DER));

	auto a = KeyPair::Load(out / "x25519_a_enc_cross.pem", pass);
	auto b = KeyPair::Load(out / "x25519_b_enc_cross.der", pass);
	ASSERT_TRUE(fn_name, a && b);

	Secret::X25519 sa(a);
	Secret::X25519 sb(b);
	auto s1 = sa.Share(b->PublicKey());
	auto s2 = sb.Share(a->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int TestCrossFormatDsaEncryptedPemDer() {
	const std::string fn_name = "TestCrossFormatDsaEncryptedPemDer";
	const fs::path out = SaveDir();
	Password pass = TestKeysPassword();

	ASSERT_TRUE(fn_name, g_dsa->SavePrivate(out / "dsa_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fn_name, g_dsa->SavePrivate(out / "dsa_enc_cross.der", pass, KeyPair::StorageFormat::DER));

	auto pemKp = KeyPair::Load(out / "dsa_enc_cross.pem", pass);
	auto derKp = KeyPair::Load(out / "dsa_enc_cross.der", pass);
	ASSERT_TRUE(fn_name, pemKp && derKp);

	Signer::DSA signer(pemKp);
	auto derPub = std::make_shared<KeyPair::DSA>(derKp->PublicKey(), std::nullopt);
	Signer::DSA verifier(derPub);

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

// ---------------------------------------------------------------------------
// Save edge cases: missing paths, public/private-only, overwrite, encryption
// ---------------------------------------------------------------------------

int TestSaveToMissingDirectoryFails() {
	const std::string fn_name = "TestSaveToMissingDirectoryFails";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp);

	const auto missing = KeysDir() / "does_not_exist_subdir";
	ASSERT_FALSE(fn_name, std::filesystem::exists(missing));
	ASSERT_FALSE(fn_name, kp->Save(missing, "rsa_missing_dir"));

	RETURN_TEST(fn_name, 0);
}

int TestSavePublicOnlyThenLoadHasNoPrivate() {
	const std::string fn_name = "TestSavePublicOnlyThenLoadHasNoPrivate";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp);

	const auto out = KeysDir() / "save_public_only";
	std::filesystem::create_directories(out);
	const auto pubPath = out / "rsa.pub.pem";
	ASSERT_TRUE(fn_name, kp->SavePublic(pubPath));

	auto loaded = KeyPair::Load(pubPath);
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_FALSE(fn_name, loaded->PrivateKey().has_value());

	RETURN_TEST(fn_name, 0);
}

int TestSavePrivateOnlyThenLoadDerivesPublicAndEncrypts() {
	const std::string fn_name = "TestSavePrivateOnlyThenLoadDerivesPublicAndEncrypts";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp);

	const auto out = KeysDir() / "save_private_only";
	std::filesystem::create_directories(out);
	const auto privPath = out / "rsa.pem";
	ASSERT_TRUE(fn_name, kp->SavePrivate(privPath));

	auto loaded = KeyPair::Load(privPath);
	ASSERT_TRUE(fn_name, loaded);
	ASSERT_TRUE(fn_name, loaded->PrivateKey().has_value());
	ASSERT_FALSE(fn_name, loaded->PublicKey().empty());

	const std::string plain = "private-only-roundtrip";
	Crypter::RSA enc(loaded);
	Crypter::RSA dec(loaded);
	StormByte::Buffer::FIFO cipher, recovered;
	ASSERT_TRUE(fn_name, enc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(plain.data()), plain.size()),
		cipher
	));
	ASSERT_TRUE(fn_name, dec.Decrypt(
		std::span<const std::byte>(cipher.Data().data(), cipher.Data().size()),
		recovered
	));
	ASSERT_EQUAL(fn_name, plain, StormByte::String::FromByteVector(recovered.Data()));

	RETURN_TEST(fn_name, 0);
}

int TestSaveOverwriteSameBaseNameStillUsable() {
	const std::string fn_name = "TestSaveOverwriteSameBaseNameStillUsable";
	auto kp1 = KeyPair::RSA::Generate(2048);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp1);
	ASSERT_TRUE(fn_name, kp2);

	const auto out = KeysDir() / "save_overwrite";
	std::filesystem::create_directories(out);
	ASSERT_TRUE(fn_name, kp1->Save(out, "rsa_ow"));
	ASSERT_TRUE(fn_name, kp2->Save(out, "rsa_ow"));

	auto loaded = KeyPair::Load(out / "rsa_ow.pub.pem", out / "rsa_ow.pem");
	ASSERT_TRUE(fn_name, loaded);

	const std::string plain = "overwrite-check";
	Crypter::RSA enc(loaded);
	Crypter::RSA dec(loaded);
	StormByte::Buffer::FIFO cipher, recovered;
	ASSERT_TRUE(fn_name, enc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(plain.data()), plain.size()),
		cipher
	));
	ASSERT_TRUE(fn_name, dec.Decrypt(
		std::span<const std::byte>(cipher.Data().data(), cipher.Data().size()),
		recovered
	));
	ASSERT_EQUAL(fn_name, plain, StormByte::String::FromByteVector(recovered.Data()));

	RETURN_TEST(fn_name, 0);
}

int TestSaveEncryptedEmptyPasswordFails() {
	const std::string fn_name = "TestSaveEncryptedEmptyPasswordFails";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp);

	const auto out = KeysDir() / "save_enc_empty_pass";
	std::filesystem::create_directories(out);
	Password empty("");
	ASSERT_FALSE(fn_name, kp->Save(out, "rsa_empty", empty));

	RETURN_TEST(fn_name, 0);
}

int TestSaveEncryptedDifferentPasswordsBothWork() {
	const std::string fn_name = "TestSaveEncryptedDifferentPasswordsBothWork";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp);

	const Password passA = TestKeysPassword();
	const Password passB("AnotherStormBytePass!");

	const auto out = KeysDir() / "save_enc_two_pass";
	std::filesystem::create_directories(out);
	ASSERT_TRUE(fn_name, kp->Save(out, "rsa_a", passA));
	ASSERT_TRUE(fn_name, kp->Save(out, "rsa_b", passB));

	auto a = KeyPair::Load(out / "rsa_a.pub.pem", out / "rsa_a.pem", passA);
	auto b = KeyPair::Load(out / "rsa_b.pub.pem", out / "rsa_b.pem", passB);
	ASSERT_TRUE(fn_name, a);
	ASSERT_TRUE(fn_name, b);
	ASSERT_FALSE(fn_name, KeyPair::Load(out / "rsa_a.pub.pem", out / "rsa_a.pem", passB));
	ASSERT_FALSE(fn_name, KeyPair::Load(out / "rsa_b.pub.pem", out / "rsa_b.pem", passA));

	RETURN_TEST(fn_name, 0);
}

int TestGenerateInvalidBitsThenNothingToSave() {
	const std::string fn_name = "TestGenerateInvalidBitsThenNothingToSave";
	ASSERT_FALSE(fn_name, KeyPair::RSA::Generate(0));
	ASSERT_FALSE(fn_name, KeyPair::RSA::Generate(9999));
	ASSERT_FALSE(fn_name, KeyPair::ECDH::Generate(0));
	ASSERT_FALSE(fn_name, KeyPair::ECDH::Generate(123));

	RETURN_TEST(fn_name, 0);
}

int TestSaveEcdhRoundTripShare() {
	const std::string fn_name = "TestSaveEcdhRoundTripShare";
	auto a0 = KeyPair::ECDH::Generate(256);
	auto b0 = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, a0);
	ASSERT_TRUE(fn_name, b0);

	const auto out = KeysDir() / "save_ecdh_share";
	std::filesystem::create_directories(out);
	ASSERT_TRUE(fn_name, a0->Save(out, "ecdh_a"));
	ASSERT_TRUE(fn_name, b0->Save(out, "ecdh_b"));

	auto a = KeyPair::Load(out / "ecdh_a.pub.pem", out / "ecdh_a.pem");
	auto b = KeyPair::Load(out / "ecdh_b.pub.pem", out / "ecdh_b.pem");
	ASSERT_TRUE(fn_name, a);
	ASSERT_TRUE(fn_name, b);

	Secret::ECDH ecdhA(a);
	Secret::ECDH ecdhB(b);
	auto s1 = ecdhA.Share(b->PublicKey());
	auto s2 = ecdhB.Share(a->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1 == s2);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// One-shot generation + save (expensive RSA/DSA only once)
	{
		const std::string setup = "SetupGenerateAndSave";
		if (GenerateAllKeypairs(setup) != 0)
			return 1;
		if (SaveAllKeypairs(setup) != 0)
			return 1;
	}

	result += TestSaveLoadRsaEncryptDecrypt();
	result += TestSaveLoadRsaHybridEncryptDecrypt();
	result += TestSaveLoadRsaSignVerify();
	result += TestSaveLoadRsaDerEncryptDecrypt();
	result += TestSaveLoadRsaPrivateOnly();

	result += TestSaveLoadDsaSignVerify();
	result += TestSaveLoadEcdsaSignVerify();
	result += TestSaveLoadEd25519SignVerify();
	result += TestSaveLoadEd25519DerSignVerify();

	result += TestSaveLoadEccEncryptDecrypt();

	result += TestSaveLoadEcdhShare();
	result += TestSaveLoadX25519Share();

	result += TestSavePublicOnlyThenLoad();
	result += TestSavePrivateOnlyThenLoad();

	result += TestSaveEncryptedRsaPrivateLoadDecrypt();
	result += TestSaveEncryptedRsaPairLoadSignVerify();
	result += TestSaveEncryptedWrongPasswordFails();
	result += TestSaveEncryptedDifferentPasswordsIndependent();
	result += TestSaveEncryptedEd25519SignVerify();
	result += TestSaveEncryptedDsaSignVerify();
	result += TestSaveEncryptedEccEncryptDecrypt();
	result += TestSaveEncryptedX25519Share();
	result += TestSaveEncryptedPublicStaysPlain();

	result += TestCrossFormatRsaPemEncryptDerDecrypt();
	result += TestCrossFormatRsaEncryptedPemDer();
	result += TestCrossFormatRsaPemSignDerVerify();
	result += TestCrossFormatDsaPemSignDerVerify();
	result += TestCrossFormatDsaEncryptedPemDer();
	result += TestCrossFormatEcdsaPemSignDerVerify();
	result += TestCrossFormatEd25519PemSignDerVerify();
	result += TestCrossFormatEd25519EncryptedPemDer();
	result += TestCrossFormatEccPemEncryptDerDecrypt();
	result += TestCrossFormatEcdhPemDerShare();
	result += TestCrossFormatX25519PemDerShare();
	result += TestCrossFormatX25519EncryptedPemDerShare();

	result += TestSaveToMissingDirectoryFails();
	result += TestSavePublicOnlyThenLoadHasNoPrivate();
	result += TestSavePrivateOnlyThenLoadDerivesPublicAndEncrypts();
	result += TestSaveOverwriteSameBaseNameStillUsable();
	result += TestSaveEncryptedEmptyPasswordFails();
	result += TestSaveEncryptedDifferentPasswordsBothWork();
	result += TestGenerateInvalidBitsThenNothingToSave();
	result += TestSaveEcdhRoundTripShare();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;

	return result;
}
