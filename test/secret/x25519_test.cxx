#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/test_handlers.h>

#include <string>

using namespace StormByte::Crypto;

int TestX25519GenerateKeyPair() {
	const std::string fn_name = "TestX25519GenerateKeyPair";

	auto keypair_result = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);
	ASSERT_TRUE(fn_name, keypair_result->HasPrivateKey());
	ASSERT_TRUE(fn_name, !keypair_result->PublicKey().empty());

	RETURN_TEST(fn_name, 0);
}

int TestX25519DeriveSharedSecretValidKeys() {
	const std::string fn_name = "TestX25519DeriveSharedSecretValidKeys";

	auto keypair_result1 = KeyPair::X25519::Generate();
	auto keypair_result2 = KeyPair::X25519::Generate();

	ASSERT_TRUE(fn_name, keypair_result1);
	ASSERT_TRUE(fn_name, keypair_result2);

	Secret::X25519 x25519_1(keypair_result1);
	Secret::X25519 x25519_2(keypair_result2);

	auto sharedSecret1 = x25519_1.Share(keypair_result2->PublicKey());
	auto sharedSecret2 = x25519_2.Share(keypair_result1->PublicKey());

	ASSERT_TRUE(fn_name, sharedSecret1.has_value());
	ASSERT_TRUE(fn_name, sharedSecret2.has_value());
	ASSERT_TRUE(fn_name, *sharedSecret1 == *sharedSecret2);

	RETURN_TEST(fn_name, 0);
}

int TestX25519DeriveSharedSecretInvalidKey() {
	const std::string fn_name = "TestX25519DeriveSharedSecretInvalidKey";

	auto keypair_result = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);

	Secret::X25519 x25519(keypair_result);

	auto sharedSecret = x25519.Share("InvalidPublicKey");
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519SharedSecretCorruptedKeys() {
	const std::string fn_name = "TestX25519SharedSecretCorruptedKeys";

	auto keypair_result = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);
	ASSERT_TRUE(fn_name, keypair_result->HasPrivateKey());

	std::string corruptedPublicKey = keypair_result->PublicKey();
	if (corruptedPublicKey.size() > 1)
		corruptedPublicKey = corruptedPublicKey.substr(0, corruptedPublicKey.size() / 2);

	auto badKp = std::make_shared<KeyPair::X25519>(
		std::move(corruptedPublicKey),
		Password("not-a-valid-x25519-private-key")
	);
	Secret::X25519 x25519(badKp);

	auto sharedSecret = x25519.Share(keypair_result->PublicKey());
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestX25519ServerClientSharedSecret() {
	const std::string fn_name = "TestX25519ServerClientSharedSecret";

	auto keypair_server = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_server);
	Secret::X25519 x25519_server(keypair_server);

	auto keypair_client = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_client);
	Secret::X25519 x25519_client(keypair_client);

	auto serverSharedSecret = x25519_server.Share(keypair_client->PublicKey());
	ASSERT_TRUE(fn_name, serverSharedSecret.has_value());

	auto clientSharedSecret = x25519_client.Share(keypair_server->PublicKey());
	ASSERT_TRUE(fn_name, clientSharedSecret.has_value());

	ASSERT_TRUE(fn_name, *serverSharedSecret == *clientSharedSecret);

	RETURN_TEST(fn_name, 0);
}

int TestX25519MaliciousThirdPartyKey() {
	const std::string fn_name = "TestX25519MaliciousThirdPartyKey";

	auto keypair_alice = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_alice);
	Secret::X25519 x25519_alice(keypair_alice);

	auto keypair_bob = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_bob);
	Secret::X25519 x25519_bob(keypair_bob);

	auto keypair_mallory = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, keypair_mallory);
	Secret::X25519 x25519_mallory(keypair_mallory);

	auto sharedSecret_alice_bob = x25519_alice.Share(keypair_bob->PublicKey());
	auto sharedSecret_bob_alice = x25519_bob.Share(keypair_alice->PublicKey());
	auto sharedSecret_mallory_alice = x25519_mallory.Share(keypair_alice->PublicKey());

	ASSERT_TRUE(fn_name, sharedSecret_alice_bob.has_value());
	ASSERT_TRUE(fn_name, sharedSecret_bob_alice.has_value());
	ASSERT_TRUE(fn_name, sharedSecret_mallory_alice.has_value());

	ASSERT_TRUE(fn_name, *sharedSecret_alice_bob == *sharedSecret_bob_alice);
	ASSERT_FALSE(fn_name, *sharedSecret_mallory_alice == *sharedSecret_alice_bob);

	RETURN_TEST(fn_name, 0);
}

int TestX25519DeriveSharedSecretStatic() {
	const std::string fn_name = "TestX25519DeriveSharedSecretStatic";
	auto a = KeyPair::X25519::Generate();
	auto b = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, a);
	ASSERT_TRUE(fn_name, b);
	auto s1 = Secret::X25519::DeriveSharedSecret(a, b->PublicKey());
	auto s2 = Secret::X25519::DeriveSharedSecret(b, a->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, *s1 == *s2);
	RETURN_TEST(fn_name, 0);
}

int TestX25519ShareWithoutPrivateKey() {
	const std::string fn_name = "TestX25519ShareWithoutPrivateKey";
	auto full = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, full);
	auto pubOnly = std::make_shared<KeyPair::X25519>(full->PublicKey());
	Secret::X25519 x(pubOnly);
	auto peer = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, peer);
	ASSERT_FALSE(fn_name, x.Share(peer->PublicKey()).has_value());
	RETURN_TEST(fn_name, 0);
}

int TestX25519ShareIdempotent() {
	const std::string fn_name = "TestX25519ShareIdempotent";
	auto a = KeyPair::X25519::Generate();
	auto b = KeyPair::X25519::Generate();
	ASSERT_TRUE(fn_name, a);
	ASSERT_TRUE(fn_name, b);
	Secret::X25519 x(a);
	auto s1 = x.Share(b->PublicKey());
	auto s2 = x.Share(b->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, *s1 == *s2);
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
	result += TestX25519DeriveSharedSecretStatic();
	result += TestX25519ShareWithoutPrivateKey();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
