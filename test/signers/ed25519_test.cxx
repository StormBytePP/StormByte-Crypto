#include <StormByte/crypto/signer.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;

int TestEd25519GenerateKeyPair() {
const std::string fn_name = "TestEd25519GenerateKeyPair";

// Generate Ed25519 key pair (no curve name needed)
auto keypair_result = KeyPair::Generate(Algorithm::Sign::Ed25519);
ASSERT_TRUE(fn_name, keypair_result.has_value());

// Verify keys are generated and not empty
ASSERT_TRUE(fn_name, keypair_result->PrivateKey().has_value());
ASSERT_TRUE(fn_name, !keypair_result->PublicKey().empty());

RETURN_TEST(fn_name, 0);
}

int TestEd25519SignAndVerify() {
const std::string fn_name = "TestEd25519SignAndVerify";
const std::string message = "Test message for Ed25519 signing";

// Generate key pair
auto keypair_result = KeyPair::Generate(Algorithm::Sign::Ed25519);
ASSERT_TRUE(fn_name, keypair_result.has_value());

Signer signer(Algorithm::Sign::Ed25519, keypair_result.value());

// Sign the message
auto signature = signer.Sign(message);
ASSERT_TRUE(fn_name, signature.has_value());

// Verify the signature
bool verified = signer.Verify(message, signature.value());
ASSERT_TRUE(fn_name, verified);

RETURN_TEST(fn_name, 0);
}

int TestEd25519VerifyWithWrongKey() {
const std::string fn_name = "TestEd25519VerifyWithWrongKey";
const std::string message = "Test message for Ed25519";

// Generate two key pairs
auto keypair_result1 = KeyPair::Generate(Algorithm::Sign::Ed25519);
auto keypair_result2 = KeyPair::Generate(Algorithm::Sign::Ed25519);

ASSERT_TRUE(fn_name, keypair_result1.has_value());
ASSERT_TRUE(fn_name, keypair_result2.has_value());

Signer signer1(Algorithm::Sign::Ed25519, keypair_result1.value());
Signer signer2(Algorithm::Sign::Ed25519, keypair_result2.value());

// Sign with first key
auto signature = signer1.Sign(message);
ASSERT_TRUE(fn_name, signature.has_value());

// Try to verify with second key (should fail)
bool verified = signer2.Verify(message, signature.value());
ASSERT_FALSE(fn_name, verified);

RETURN_TEST(fn_name, 0);
}

int TestEd25519VerifyWithWrongMessage() {
const std::string fn_name = "TestEd25519VerifyWithWrongMessage";
const std::string message = "Original message";
const std::string modified_message = "Modified message";

// Generate key pair
auto keypair_result = KeyPair::Generate(Algorithm::Sign::Ed25519);
ASSERT_TRUE(fn_name, keypair_result.has_value());

Signer signer(Algorithm::Sign::Ed25519, keypair_result.value());

// Sign the original message
auto signature = signer.Sign(message);
ASSERT_TRUE(fn_name, signature.has_value());

// Try to verify modified message (should fail)
bool verified = signer.Verify(modified_message, signature.value());
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
