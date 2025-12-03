#include <StormByte/crypto/secret.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;

int TestX25519GenerateKeyPair() {
	const std::string fn_name = "TestX25519GenerateKeyPair";

	// Generate X25519 key pair (no curve name needed - Curve25519 is fixed)
	auto keypair_result = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	// Verify keys are generated and not empty
	ASSERT_TRUE(fn_name, keypair_result->PrivateKey().has_value());
	ASSERT_TRUE(fn_name, !keypair_result->PublicKey().empty());

	RETURN_TEST(fn_name, 0);
}

int TestX25519DeriveSharedSecretValidKeys() {
	const std::string fn_name = "TestX25519DeriveSharedSecretValidKeys";

	// Generate two key pairs
	auto keypair_result1 = KeyPair::Generate(Algorithm::SecretShare::X25519);
	auto keypair_result2 = KeyPair::Generate(Algorithm::SecretShare::X25519);

	ASSERT_TRUE(fn_name, keypair_result1.has_value());
	ASSERT_TRUE(fn_name, keypair_result2.has_value());

	// Create Secret objects
	Secret x25519_1(Algorithm::SecretShare::X25519, keypair_result1.value());
	Secret x25519_2(Algorithm::SecretShare::X25519, keypair_result2.value());

	// Set peer public keys
	x25519_1.PeerPublicKey(keypair_result2->PublicKey());
	x25519_2.PeerPublicKey(keypair_result1->PublicKey());

	// Derive shared secrets
	auto sharedSecret1 = x25519_1.Content();
	auto sharedSecret2 = x25519_2.Content();

	ASSERT_TRUE(fn_name, sharedSecret1.has_value());
	ASSERT_TRUE(fn_name, sharedSecret2.has_value());

	// Verify both parties derived the same shared secret
	ASSERT_EQUAL(fn_name, sharedSecret1.value(), sharedSecret2.value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519DeriveSharedSecretInvalidKey() {
	const std::string fn_name = "TestX25519DeriveSharedSecretInvalidKey";

	// Generate a valid key pair
	auto keypair_result = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Secret x25519(Algorithm::SecretShare::X25519, keypair_result.value());

	// Attempt to derive shared secret without setting peer public key
	auto sharedSecret = x25519.Content();
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519SharedSecretCorruptedKeys() {
	const std::string fn_name = "TestX25519SharedSecretCorruptedKeys";

	// Generate a valid key pair
	auto keypair_result = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	// Use corrupted keys (truncate them to half size)
	std::string corruptedPrivateKey = keypair_result->PrivateKey()->substr(0, keypair_result->PrivateKey()->size() / 2);
	std::string corruptedPublicKey = keypair_result->PublicKey().substr(0, keypair_result->PublicKey().size() / 2);

	Secret x25519(Algorithm::SecretShare::X25519, {corruptedPrivateKey, corruptedPublicKey});

	auto sharedSecret = x25519.Content();
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519ServerClientSharedSecret() {
	const std::string fn_name = "TestX25519ServerClientSharedSecret";

	// Step 1: Server generates its X25519 key pair
	auto keypair_server = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_server.has_value());
	Secret x25519_server(Algorithm::SecretShare::X25519, keypair_server.value());

	// Step 2: Client generates its X25519 key pair
	auto keypair_client = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_client.has_value());
	Secret x25519_client(Algorithm::SecretShare::X25519, keypair_client.value());

	x25519_server.PeerPublicKey(keypair_client->PublicKey());
	x25519_client.PeerPublicKey(keypair_server->PublicKey());

	// Step 3: Server derives the shared secret using its private key and the client's public key
	auto serverSharedSecret = x25519_server.Content();
	ASSERT_TRUE(fn_name, serverSharedSecret.has_value());

	// Step 4: Client derives the shared secret using its private key and the server's public key
	auto clientSharedSecret = x25519_client.Content();
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
	auto keypair_alice = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_alice.has_value());
	Secret x25519_alice(Algorithm::SecretShare::X25519, keypair_alice.value());

	auto keypair_bob = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_bob.has_value());
	Secret x25519_bob(Algorithm::SecretShare::X25519, keypair_bob.value());

	// Mallory generates a malicious but valid key pair
	auto keypair_mallory = KeyPair::Generate(Algorithm::SecretShare::X25519);
	ASSERT_TRUE(fn_name, keypair_mallory.has_value());
	Secret x25519_mallory(Algorithm::SecretShare::X25519, keypair_mallory.value());

	// Alice and Bob exchange public keys correctly
	x25519_alice.PeerPublicKey(keypair_bob->PublicKey());
	x25519_bob.PeerPublicKey(keypair_alice->PublicKey());

	// Mallory attempts to derive a shared secret using Alice's public key
	x25519_mallory.PeerPublicKey(keypair_alice->PublicKey());

	// Derive the shared secrets
	auto sharedSecret_alice_bob = x25519_alice.Content();
	auto sharedSecret_bob_alice = x25519_bob.Content();
	auto sharedSecret_mallory_alice = x25519_mallory.Content();

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
