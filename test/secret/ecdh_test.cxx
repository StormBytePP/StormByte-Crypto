#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/test_handlers.h>

#include <string>

using namespace StormByte::Crypto;

int TestECDHGenerateKeyPairValidCurve() {
	const std::string fn_name = "TestECDHGenerateKeyPairValidCurve";
	constexpr const unsigned short curve_bits = 256;

	auto keypair_result = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Secret::ECDH ecdh(keypair_result);

	RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairInvalidCurve() {
	const std::string fn_name = "TestECDHGenerateKeyPairInvalidCurve";

	auto keypair_result = KeyPair::ECDH::Generate(9999);
	ASSERT_FALSE(fn_name, keypair_result);

	RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretValidKeys() {
	const std::string fn_name = "TestECDHDeriveSharedSecretValidKeys";
	constexpr const unsigned short curve_bits = 256;

	auto keypair_result1 = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result1);
	Secret::ECDH ecdh1(keypair_result1);

	auto keypair_result2 = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result2);
	Secret::ECDH ecdh2(keypair_result2);

	auto sharedSecret1 = ecdh1.Share(keypair_result2->PublicKey());
	auto sharedSecret2 = ecdh2.Share(keypair_result1->PublicKey());

	ASSERT_TRUE(fn_name, sharedSecret1.has_value());
	ASSERT_TRUE(fn_name, sharedSecret2.has_value());
	ASSERT_TRUE(fn_name, *sharedSecret1 == *sharedSecret2);

	RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretInvalidKey() {
	const std::string fn_name = "TestECDHDeriveSharedSecretInvalidPrivateKey";
	constexpr const unsigned short curve_bits = 256;

	auto keypair_result = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Secret::ECDH ecdh(keypair_result);

	auto sharedSecret = ecdh.Share("InvalidPublicKey");
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairDifferentCurves() {
	const std::string fn_name = "TestECDHGenerateKeyPairDifferentCurves";

	auto keypair_result1 = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, keypair_result1);

	auto keypair_result2 = KeyPair::ECDH::Generate(384);
	ASSERT_TRUE(fn_name, keypair_result2);

	auto keypair_result3 = KeyPair::ECDH::Generate(521);
	ASSERT_TRUE(fn_name, keypair_result3);

	ASSERT_TRUE(fn_name, keypair_result1->HasPrivateKey());
	ASSERT_TRUE(fn_name, keypair_result2->HasPrivateKey());
	ASSERT_TRUE(fn_name, keypair_result3->HasPrivateKey());
	ASSERT_FALSE(fn_name, keypair_result1->PrivateKey()->Empty());
	ASSERT_FALSE(fn_name, keypair_result2->PrivateKey()->Empty());
	ASSERT_FALSE(fn_name, keypair_result3->PrivateKey()->Empty());
	ASSERT_FALSE(fn_name, keypair_result1->PublicKey().empty());
	ASSERT_FALSE(fn_name, keypair_result2->PublicKey().empty());
	ASSERT_FALSE(fn_name, keypair_result3->PublicKey().empty());

	RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretDifferentCurves() {
	const std::string fn_name = "TestECDHSharedSecretDifferentCurves";

	auto keypair_result1 = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, keypair_result1);
	Secret::ECDH ecdh1(keypair_result1, 256);

	auto keypair_result2 = KeyPair::ECDH::Generate(384);
	ASSERT_TRUE(fn_name, keypair_result2);

	auto sharedSecret = ecdh1.Share(keypair_result2->PublicKey());
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretCorruptedKeys() {
	const std::string fn_name = "TestECDHSharedSecretCorruptedKeys";
	constexpr const unsigned short curve_bits = 256;

	auto keypair_result = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	ASSERT_TRUE(fn_name, keypair_result->HasPrivateKey());

	std::string corruptedPublicKey = keypair_result->PublicKey();
	if (corruptedPublicKey.size() > 1)
		corruptedPublicKey = corruptedPublicKey.substr(0, corruptedPublicKey.size() / 2);

	auto badKp = std::make_shared<KeyPair::ECDH>(
		std::move(corruptedPublicKey),
		Password("not-a-valid-ecdh-private-key")
	);
	Secret::ECDH ecdh(badKp, curve_bits);

	auto sharedSecret = ecdh.Share(keypair_result->PublicKey());
	ASSERT_FALSE(fn_name, sharedSecret.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECDHServerClientSharedSecret() {
	const std::string fn_name = "TestECDHServerClientSharedSecret";
	constexpr const unsigned short curve_bits = 256;

	auto keypair_server = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_server);
	Secret::ECDH ecdh_server(keypair_server);

	auto keypair_client = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_client);
	Secret::ECDH ecdh_client(keypair_client);

	auto serverSharedSecret = ecdh_server.Share(keypair_client->PublicKey());
	ASSERT_TRUE(fn_name, serverSharedSecret.has_value());

	auto clientSharedSecret = ecdh_client.Share(keypair_server->PublicKey());
	ASSERT_TRUE(fn_name, clientSharedSecret.has_value());

	ASSERT_TRUE(fn_name, *serverSharedSecret == *clientSharedSecret);

	RETURN_TEST(fn_name, 0);
}

int TestECDHMaliciousThirdPartyKey() {
	const std::string fn_name = "TestECDHMaliciousThirdPartyKey";
	constexpr const unsigned short curve_bits = 256;

	auto keypair_alice = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_alice);
	Secret::ECDH ecdh_alice(keypair_alice);

	auto keypair_bob = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_bob);
	Secret::ECDH ecdh_bob(keypair_bob);

	auto keypair_mallory = KeyPair::ECDH::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_mallory);
	Secret::ECDH ecdh_mallory(keypair_mallory);

	auto sharedSecret_alice_bob = ecdh_alice.Share(keypair_bob->PublicKey());
	auto sharedSecret_bob_alice = ecdh_bob.Share(keypair_alice->PublicKey());
	auto sharedSecret_mallory_alice = ecdh_mallory.Share(keypair_alice->PublicKey());

	ASSERT_TRUE(fn_name, sharedSecret_alice_bob.has_value());
	ASSERT_TRUE(fn_name, sharedSecret_bob_alice.has_value());
	ASSERT_TRUE(fn_name, sharedSecret_mallory_alice.has_value());

	ASSERT_TRUE(fn_name, *sharedSecret_alice_bob == *sharedSecret_bob_alice);
	ASSERT_FALSE(fn_name, *sharedSecret_mallory_alice == *sharedSecret_alice_bob);

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
