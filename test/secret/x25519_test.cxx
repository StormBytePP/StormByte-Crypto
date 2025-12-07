#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;

int TestX25519GenerateKeyPair() {
	const std::string fn_name = "TestX25519GenerateKeyPair";

	// Generate X25519 key pair (no curve name needed - Curve25519 is fixed)
	auto keypair_result = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);

	// Verify keys are generated and not empty
	ASSERT_TRUE(fn_name, keypair_result->PrivateKey().has_value());
	ASSERT_TRUE(fn_name, !keypair_result->PublicKey().empty());

	RETURN_TEST(fn_name, 0);
}

int TestX25519DeriveSharedSecretValidKeys() {
	const std::string fn_name = "TestX25519DeriveSharedSecretValidKeys";

	// Generate two key pairs
	auto keypair_result1 = KeyPair::X25519::Generate();
	auto keypair_result2 = KeyPair::X25519::Generate();

	ASSERT_TRUE(fn_name, keypair_result1);
	ASSERT_TRUE(fn_name, keypair_result2);

	// Create Secret objects
	Secret::X25519 x25519_1(keypair_result1);
	Secret::X25519 x25519_2(keypair_result2);

	// Derive shared secrets
	auto sharedSecret1 = x25519_1.Share(keypair_result2->PublicKey());
	auto sharedSecret2 = x25519_2.Share(keypair_result1->PublicKey());

	ASSERT_TRUE(fn_name, sharedSecret1.has_value());
	ASSERT_TRUE(fn_name, sharedSecret2.has_value());

	// Verify both parties derived the same shared secret
	ASSERT_EQUAL(fn_name, sharedSecret1.value(), sharedSecret2.value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519DeriveSharedSecretInvalidKey() {
	const std::string fn_name = "TestX25519DeriveSharedSecretInvalidKey";

	// Generate a valid key pair
	auto keypair_result = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);

	Secret::X25519 x25519(keypair_result);

	// Attempt to derive shared secret without setting peer public key
	auto sharedSecret = x25519.Share("InvalidPublicKey");
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519SharedSecretCorruptedKeys() {
	const std::string fn_name = "TestX25519SharedSecretCorruptedKeys";

	// Generate a valid key pair
	auto keypair_result = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);

	// Use corrupted keys (truncate them to half size)
	std::string corruptedPrivateKey = keypair_result->PrivateKey()->substr(0, keypair_result->PrivateKey()->size() / 2);
	std::string corruptedPublicKey = keypair_result->PublicKey().substr(0, keypair_result->PublicKey().size() / 2);

	Secret::X25519 x25519({corruptedPrivateKey, corruptedPublicKey});

	auto sharedSecret = x25519.Share(keypair_result->PublicKey());
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519ServerClientSharedSecret() {
	const std::string fn_name = "TestX25519ServerClientSharedSecret";

	// Step 1: Server generates its X25519 key pair
	auto keypair_server = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_server);
	Secret::X25519 x25519_server(keypair_server);

	// Step 2: Client generates its X25519 key pair
	auto keypair_client = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_client);
	Secret::X25519 x25519_client(keypair_client);

	// Step 3: Server derives the shared secret using its private key and the client's public key
	auto serverSharedSecret = x25519_server.Share(keypair_client->PublicKey());
	ASSERT_TRUE(fn_name, serverSharedSecret.has_value());

	// Step 4: Client derives the shared secret using its private key and the server's public key
	auto clientSharedSecret = x25519_client.Share(keypair_server->PublicKey());
	ASSERT_TRUE(fn_name, clientSharedSecret.has_value());

	// Step 5: Verify that both shared secrets are identical
	ASSERT_EQUAL(fn_name, serverSharedSecret.value(), clientSharedSecret.value());

	// Step 6: (Commented) The shared secret can now be used as a secure password for AES encryption/decryption
	// Example:
	// std::string aesPassword = serverSharedSecret.value();
	// Use `aesPassword` for AES encryption/decryption in both server and client.

	RETURN_TEST(fn_name, 0);
}

int TestX25519MaliciousThirdPartyKey() {
	const std::string fn_name = "TestX25519MaliciousThirdPartyKey";

	// Alice and Bob generate their legitimate key pairs
	auto keypair_alice = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_alice);
	Secret::X25519 x25519_alice(keypair_alice);

	auto keypair_bob = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_bob);
	Secret::X25519 x25519_bob(keypair_bob);

	// Mallory generates a malicious but valid key pair
	auto keypair_mallory = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_mallory);
	Secret::X25519 x25519_mallory(keypair_mallory);

	// Alice and Bob exchange public keys correctly
	// Mallory attempts to derive a shared secret using Alice's public key

	// Derive the shared secrets
	auto sharedSecret_alice_bob = x25519_alice.Share(keypair_bob->PublicKey());
	auto sharedSecret_bob_alice = x25519_bob.Share(keypair_alice->PublicKey());
	auto sharedSecret_mallory_alice = x25519_mallory.Share(keypair_alice->PublicKey());

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

	result += TestX25519GenerateKeyPair();
	result += TestX25519DeriveSharedSecretValidKeys();
	result += TestX25519DeriveSharedSecretInvalidKey();
	result += TestX25519SharedSecretCorruptedKeys();
	result += TestX25519ServerClientSharedSecret();
	result += TestX25519MaliciousThirdPartyKey();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
