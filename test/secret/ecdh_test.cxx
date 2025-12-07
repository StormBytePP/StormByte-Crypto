#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;

int TestECDHGenerateKeyPairValidCurve() {
	const std::string fn_name = "TestECDHGenerateKeyPairValidCurve";
	constexpr const unsigned short curve_bits = 256;

	// Generate key pair for a valid curve
	auto keypair_result = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Secret::ECDH ecdh(keypair_result);

	RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairInvalidCurve() {
	const std::string fn_name = "TestECDHGenerateKeyPairInvalidCurve";

	// Attempt to generate key pair for an invalid curve
	auto keypair_result = KeyPair::ECDH::Generate(9999); // Invalid curve bits
	ASSERT_FALSE(fn_name, keypair_result);

	RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretValidKeys() {
	const std::string fn_name = "TestECDHDeriveSharedSecretValidKeys";
	constexpr const unsigned short curve_bits = 256;

	// Generate key pairs for two parties
	auto keypair_result1 = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result1);
	Secret::ECDH ecdh1(keypair_result1);

	auto keypair_result2 = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result2);
	Secret::ECDH ecdh2(keypair_result2);

	// Derive shared secrets
	auto sharedSecret1 = ecdh1.Share(keypair_result2->PublicKey());
	auto sharedSecret2 = ecdh2.Share(keypair_result1->PublicKey());

	ASSERT_TRUE(fn_name, sharedSecret1.has_value());
	ASSERT_TRUE(fn_name, sharedSecret2.has_value());
	ASSERT_EQUAL(fn_name, sharedSecret1.value(), sharedSecret2.value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretInvalidKey() {
	const std::string fn_name = "TestECDHDeriveSharedSecretInvalidPrivateKey";
	constexpr const unsigned short curve_bits = 256;

	// Generate a valid key pair
	auto keypair_result = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Secret::ECDH ecdh(keypair_result);

	// Use an invalid private key
	auto sharedSecret = ecdh.Share("InvalidPublicKey");
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairDifferentCurves() {
	const std::string fn_name = "TestECDHGenerateKeyPairDifferentCurves";
	const unsigned short curve_bits1 = 256;
	const unsigned short curve_bits2 = 384;
	const unsigned short curve_bits3 = 521;

	// Generate key pairs for different curves
	auto keypair_result1 = KeyPair::ECDH::Generate(curve_bits1);
	ASSERT_TRUE(fn_name, keypair_result1);
	Secret::ECDH ecdh1(keypair_result1);

	auto keypair_result2 = KeyPair::ECDH::Generate(curve_bits2);
	ASSERT_TRUE(fn_name, keypair_result2);
	Secret::ECDH ecdh2(keypair_result2);

	auto keypair_result3 = KeyPair::ECDH::Generate(curve_bits3);
	ASSERT_TRUE(fn_name, keypair_result3);
	Secret::ECDH ecdh3(keypair_result3);

	ASSERT_TRUE(fn_name, keypair_result1);
	ASSERT_TRUE(fn_name, keypair_result2);
	ASSERT_TRUE(fn_name, keypair_result3);

	ASSERT_FALSE(fn_name, keypair_result1->PrivateKey()->empty());
	ASSERT_FALSE(fn_name, keypair_result2->PrivateKey()->empty());
	ASSERT_FALSE(fn_name, keypair_result3->PrivateKey()->empty());

	ASSERT_FALSE(fn_name, keypair_result1->PublicKey().empty());
	ASSERT_FALSE(fn_name, keypair_result2->PublicKey().empty());
	ASSERT_FALSE(fn_name, keypair_result3->PublicKey().empty());

	RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretDifferentCurves() {
	const std::string fn_name = "TestECDHSharedSecretDifferentCurves";
	const unsigned short curve_bits1 = 256;
	const unsigned short curve_bits2 = 384;

	// Generate key pairs for different curves
	auto keypair_result1 = KeyPair::ECDH::Generate(curve_bits1);
	ASSERT_TRUE(fn_name, keypair_result1);
	Secret::ECDH ecdh1(keypair_result1);

	auto keypair_result2 = KeyPair::ECDH::Generate(curve_bits2);
	ASSERT_TRUE(fn_name, keypair_result2);
	Secret::ECDH ecdh2(keypair_result2);
	ASSERT_TRUE(fn_name, keypair_result1);
	ASSERT_TRUE(fn_name, keypair_result2);

	// Attempt to derive shared secret between different curves
	auto sharedSecret = ecdh1.Share(keypair_result2->PublicKey());
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretCorruptedKeys() {
	const std::string fn_name = "TestECDHSharedSecretCorruptedKeys";
	constexpr const unsigned short curve_bits = 256;

	// Generate a valid key pair
	auto keypair_result = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);

	// Use corrupted keys
	std::string corruptedPrivateKey = keypair_result->PrivateKey()->substr(0, keypair_result->PrivateKey()->size() / 2);
	std::string corruptedPublicKey = keypair_result->PublicKey().substr(0, keypair_result->PublicKey().size() / 2);

	Secret::ECDH ecdh({corruptedPrivateKey, corruptedPublicKey});

	auto sharedSecret = ecdh.Share(corruptedPublicKey);
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHServerClientSharedSecret() {
	const std::string fn_name = "TestECDHServerClientSharedSecret";
	constexpr const unsigned short curve_bits = 256;

	// Step 1: Server generates its ECDH key pair
	auto keypair_server = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_server);
	Secret::ECDH ecdh_server(keypair_server);

	// Step 2: Client generates its ECDH key pair
	auto keypair_client = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_client);
	Secret::ECDH ecdh_client(keypair_client);

	// Step 3: Server derives the shared secret using its private key and the client's public key
	auto serverSharedSecret = ecdh_server.Share(keypair_client->PublicKey());
	ASSERT_TRUE(fn_name, serverSharedSecret);

	// Step 4: Client derives the shared secret using its private key and the server's public key
	auto clientSharedSecret = ecdh_client.Share(keypair_server->PublicKey());
	ASSERT_TRUE(fn_name, clientSharedSecret.has_value());

	// Step 5: Verify that both shared secrets are identical
	ASSERT_EQUAL(fn_name, serverSharedSecret.value(), clientSharedSecret.value());

	// Step 6: (Commented) The shared secret can now be used as a secure password for AES encryption/decryption
	// Example:
	// std::string aesPassword = serverSharedSecret.value();
	// Use `aesPassword` for AES encryption/decryption in both server and client.

	RETURN_TEST(fn_name, 0);
}

int TestECDHMaliciousThirdPartyKey() {
	const std::string fn_name = "TestECDHMaliciousThirdPartyKey";
	constexpr const unsigned short curve_bits = 256;

	// Alice and Bob generate their legitimate key pairs
	auto keypair_alice = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_alice);
	Secret::ECDH ecdh_alice(keypair_alice);

	auto keypair_bob = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_bob);
	Secret::ECDH ecdh_bob(keypair_bob);

	// Mallory generates a malicious but valid key pair
	auto keypair_mallory = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_mallory);
	Secret::ECDH ecdh_mallory(keypair_mallory);

	// Alice and Bob exchange public keys correctly
	// Mallory attempts to derive a shared secret using Alice's public key

	// Derive the shared secrets
	auto sharedSecret_alice_bob = ecdh_alice.Share(keypair_bob->PublicKey());
	auto sharedSecret_bob_alice = ecdh_bob.Share(keypair_alice->PublicKey());
	auto sharedSecret_mallory_alice = ecdh_mallory.Share(keypair_alice->PublicKey());

	ASSERT_TRUE(fn_name, sharedSecret_alice_bob.has_value());
	ASSERT_TRUE(fn_name, sharedSecret_bob_alice.has_value());
	ASSERT_TRUE(fn_name, sharedSecret_mallory_alice.has_value());

	// Verify Alice and Bob share the same secret
	ASSERT_EQUAL(fn_name, sharedSecret_alice_bob.value(), sharedSecret_bob_alice.value());

	// Verify Mallory's derived secret is different from Alice-Bob's shared secret
	ASSERT_NOT_EQUAL(fn_name, sharedSecret_mallory_alice.value(), sharedSecret_alice_bob.value());

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestECDHGenerateKeyPairValidCurve();
	result += TestECDHGenerateKeyPairInvalidCurve();
	result += TestECDHDeriveSharedSecretValidKeys();
	result += TestECDHGenerateKeyPairDifferentCurves();
	result += TestECDHSharedSecretDifferentCurves();
	result += TestECDHSharedSecretCorruptedKeys();
	result += TestECDHServerClientSharedSecret();
	result += TestECDHMaliciousThirdPartyKey();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}