#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestEd25519GenerateKeyPair() {
	const std::string fn_name = "TestEd25519GenerateKeyPair";

	// Generate Ed25519 key pair (no curve name needed)
	auto keypair_result = KeyPair::ED25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);

	// Verify keys are generated and not empty
	ASSERT_TRUE(fn_name, keypair_result->PrivateKey().has_value());
	ASSERT_TRUE(fn_name, !keypair_result->PublicKey().empty());

	RETURN_TEST(fn_name, 0);
}

int TestEd25519SignAndVerify() {
	const std::string fn_name = "TestEd25519SignAndVerify";
	const std::string message = "Test message for Ed25519 signing";

	// Generate key pair
	auto keypair_result = KeyPair::ED25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);

	Signer::ED25519 signer(keypair_result);

	// Sign the message
	FIFO signed_data;
	auto sign_result = signer.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);

	// Verify the signature
	bool verified = signer.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), StormByte::String::FromByteVector(signed_data.Data()));
	ASSERT_TRUE(fn_name, verified);

	RETURN_TEST(fn_name, 0);
}

int TestEd25519VerifyWithWrongKey() {
	const std::string fn_name = "TestEd25519VerifyWithWrongKey";
	const std::string message = "Test message for Ed25519";

	// Generate two key pairs
	auto keypair_result1 = KeyPair::ED25519::Generate();
	auto keypair_result2 = KeyPair::ED25519::Generate();

	ASSERT_TRUE(fn_name, keypair_result1);
	ASSERT_TRUE(fn_name, keypair_result2);

	Signer::ED25519 signer1(keypair_result1);
	Signer::ED25519 signer2(keypair_result2);

	// Sign with first key
	FIFO signed_data;
	auto sign_result = signer1.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);

	// Try to verify with second key (should fail)
	bool verified = signer2.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), StormByte::String::FromByteVector(signed_data.Data()));
	ASSERT_FALSE(fn_name, verified);

	RETURN_TEST(fn_name, 0);
}

int TestEd25519VerifyWithWrongMessage() {
	const std::string fn_name = "TestEd25519VerifyWithWrongMessage";
	const std::string message = "Original message";
	const std::string modified_message = "Modified message";

	// Generate key pair
	auto keypair_result = KeyPair::ED25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);

	Signer::ED25519 signer(keypair_result);

	// Sign the original message
	FIFO signed_data;
	auto sign_result = signer.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);

	// Try to verify modified message (should fail)
	bool verified = signer.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(modified_message.data()), modified_message.size()), StormByte::String::FromByteVector(signed_data.Data()));
	ASSERT_FALSE(fn_name, verified);

	RETURN_TEST(fn_name, 0);
}

int main() {
int result = 0;

result += TestEd25519GenerateKeyPair();
result += TestEd25519SignAndVerify();
result += TestEd25519VerifyWithWrongKey();
result += TestEd25519VerifyWithWrongMessage();

if (result == 0) {
std::cout << "All tests passed!" << std::endl;
} else {
std::cout << result << " tests failed." << std::endl;
}
return result;
}
