#include <StormByte/crypto/secret.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;

int TestECDHGenerateKeyPairValidCurve() {
	const std::string fn_name = "TestECDHGenerateKeyPairValidCurve";
	const std::string curve_name = "secp256r1";

	// Generate key pair for a valid curve
	auto keypair_result = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Secret ecdh(Algorithm::SecretShare::ECDH, keypair_result.value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairInvalidCurve() {
	const std::string fn_name = "TestECDHGenerateKeyPairInvalidCurve";

	// Attempt to generate key pair for an invalid curve
	auto keypair_result = KeyPair::Generate(Algorithm::SecretShare::ECDH, "invalid_curve");
	ASSERT_FALSE(fn_name, keypair_result.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretValidKeys() {
	const std::string fn_name = "TestECDHDeriveSharedSecretValidKeys";
	const std::string curve_name = "secp256r1";

	// Generate key pairs for two parties
	auto keypair_result1 = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_result1.has_value());
	Secret ecdh1(Algorithm::SecretShare::ECDH, keypair_result1.value());

	auto keypair_result2 = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_result2.has_value());
	Secret ecdh2(Algorithm::SecretShare::ECDH, keypair_result2.value());

	// Set reciprocal keys
	ecdh1.PeerPublicKey(keypair_result2->PublicKey());
	ecdh2.PeerPublicKey(keypair_result1->PublicKey());

	// Derive shared secrets
	auto sharedSecret1 = ecdh1.Content();
	auto sharedSecret2 = ecdh2.Content();

	ASSERT_TRUE(fn_name, sharedSecret1.has_value());
	ASSERT_TRUE(fn_name, sharedSecret2.has_value());
	ASSERT_EQUAL(fn_name, sharedSecret1.value(), sharedSecret2.value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretInvalidKey() {
	const std::string fn_name = "TestECDHDeriveSharedSecretInvalidPrivateKey";
	const std::string curve_name = "secp256r1";

	// Generate a valid key pair
	auto keypair_result = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Secret ecdh(Algorithm::SecretShare::ECDH, keypair_result.value());

	// Use an invalid private key
	auto sharedSecret = ecdh.Content();
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairDifferentCurves() {
	const std::string fn_name = "TestECDHGenerateKeyPairDifferentCurves";
	const std::string curve_name1 = "secp256r1";
	const std::string curve_name2 = "secp384r1";
	const std::string curve_name3 = "secp521r1";

	// Generate key pairs for different curves
	auto keypair_result1 = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name1);
	ASSERT_TRUE(fn_name, keypair_result1.has_value());
	Secret ecdh1(Algorithm::SecretShare::ECDH, keypair_result1.value());

	auto keypair_result2 = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name2);
	ASSERT_TRUE(fn_name, keypair_result2.has_value());
	Secret ecdh2(Algorithm::SecretShare::ECDH, keypair_result2.value());

	auto keypair_result3 = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name3);
	ASSERT_TRUE(fn_name, keypair_result3.has_value());
	Secret ecdh3(Algorithm::SecretShare::ECDH, keypair_result3.value());

	ASSERT_TRUE(fn_name, keypair_result1.has_value());
	ASSERT_TRUE(fn_name, keypair_result2.has_value());
	ASSERT_TRUE(fn_name, keypair_result3.has_value());

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
	const std::string curve_name1 = "secp256r1";
	const std::string curve_name2 = "secp384r1";

	// Generate key pairs for different curves
	auto keypair_result1 = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name1);
	ASSERT_TRUE(fn_name, keypair_result1.has_value());
	Secret ecdh1(Algorithm::SecretShare::ECDH, keypair_result1.value());

	auto keypair_result2 = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name2);
	ASSERT_TRUE(fn_name, keypair_result2.has_value());
	Secret ecdh2(Algorithm::SecretShare::ECDH, keypair_result2.value());

	ASSERT_TRUE(fn_name, keypair_result1.has_value());
	ASSERT_TRUE(fn_name, keypair_result2.has_value());

	// Binding keys
	ecdh1.PeerPublicKey(keypair_result2->PublicKey());
	ecdh2.PeerPublicKey(keypair_result1->PublicKey());

	// Attempt to derive shared secret between different curves
	auto sharedSecret = ecdh1.Content();
	ASSERT_FALSE(fn_name, sharedSecret.has_value());
	ASSERT_TRUE(fn_name, sharedSecret.error() != nullptr);

	RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretCorruptedKeys() {
	const std::string fn_name = "TestECDHSharedSecretCorruptedKeys";
	const std::string curve_name = "secp256r1";

	// Generate a valid key pair
	auto keypair_result = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	// Use corrupted keys
	std::string corruptedPrivateKey = keypair_result->PrivateKey()->substr(0, keypair_result->PrivateKey()->size() / 2);
	std::string corruptedPublicKey = keypair_result->PublicKey().substr(0, keypair_result->PublicKey().size() / 2);

	Secret ecdh(Algorithm::SecretShare::ECDH, {corruptedPrivateKey, corruptedPublicKey});

	auto sharedSecret = ecdh.Content();
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHServerClientSharedSecret() {
	const std::string fn_name = "TestECDHServerClientSharedSecret";
	const std::string curve_name = "secp256r1";

	// Step 1: Server generates its ECDH key pair
	auto keypair_server = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_server.has_value());
	Secret ecdh_server(Algorithm::SecretShare::ECDH, keypair_server.value());

	// Step 2: Client generates its ECDH key pair
	auto keypair_client = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_client.has_value());
	Secret ecdh_client(Algorithm::SecretShare::ECDH, keypair_client.value());

	ecdh_server.PeerPublicKey(keypair_client->PublicKey());
	ecdh_client.PeerPublicKey(keypair_server->PublicKey());

	// Step 3: Server derives the shared secret using its private key and the client's public key
	auto serverSharedSecret = ecdh_server.Content();
	ASSERT_TRUE(fn_name, serverSharedSecret.has_value());

	// Step 4: Client derives the shared secret using its private key and the server's public key
	auto clientSharedSecret = ecdh_client.Content();
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
	const std::string curve_name = "secp256r1";

	// Alice and Bob generate their legitimate key pairs
	auto keypair_alice = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_alice.has_value());
	Secret ecdh_alice(Algorithm::SecretShare::ECDH, keypair_alice.value());

	auto keypair_bob = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_bob.has_value());
	Secret ecdh_bob(Algorithm::SecretShare::ECDH, keypair_bob.value());

	// Mallory generates a malicious but valid key pair
	auto keypair_mallory = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
	ASSERT_TRUE(fn_name, keypair_mallory.has_value());
	Secret ecdh_mallory(Algorithm::SecretShare::ECDH, keypair_mallory.value());

	// Alice and Bob exchange public keys correctly
	ecdh_alice.PeerPublicKey(keypair_bob->PublicKey());
	ecdh_bob.PeerPublicKey(keypair_alice->PublicKey());

	// Mallory attempts to derive a shared secret using Alice's public key
	ecdh_mallory.PeerPublicKey(keypair_alice->PublicKey());

	// Derive the shared secrets
	auto sharedSecret_alice_bob = ecdh_alice.Content();
	auto sharedSecret_bob_alice = ecdh_bob.Content();
	auto sharedSecret_mallory_alice = ecdh_mallory.Content();

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