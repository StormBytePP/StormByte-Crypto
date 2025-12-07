#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/random.hxx>

#include <dsa.h>

using namespace StormByte::Crypto::KeyPair;

DSA::PointerType DSA::Generate(unsigned short key_size) noexcept {
	if (key_size != 1024 && key_size != 2048 && key_size != 3072 && key_size != 4096)
		return nullptr;
	
	try {
		// Generate DSA domain parameters
		CryptoPP::DL_GroupParameters_DSA params;
		params.GenerateRandomWithKeySize(RNG(), key_size);
		
		// Extract domain parameters
		const CryptoPP::Integer& p = params.GetModulus();
		const CryptoPP::Integer& q = params.GetSubgroupOrder();
		const CryptoPP::Integer& g = params.GetSubgroupGenerator();
		
		// Generate random private exponent
		CryptoPP::Integer x(RNG(), CryptoPP::Integer::One(), q - CryptoPP::Integer::One());
		
		// Initialize private key with domain parameters and exponent
		// Note: We avoid using Initialize(params, x) or GenerateRandomWithKeySize
		// because they use NameValuePairs internally, which has a bug in Crypto++ 8.9.0
		// when built with clang/libc++ that causes RTTI pointer type mismatches.
		CryptoPP::DSA::PrivateKey privateKey;
		privateKey.AccessGroupParameters().Initialize(p, q, g);
		privateKey.SetPrivateExponent(x);

		// Generate the public key
		// Note: We use MakePublicKey instead of AssignFrom to avoid the same
		// NameValuePairs bug in Crypto++ 8.9.0 + clang/libc++
		CryptoPP::DSA::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		// Validate the keys
		if (!privateKey.Validate(RNG(), 3))
			return nullptr;
		
		if (!publicKey.Validate(RNG(), 3)) {
			return nullptr;
		}

		// Serialize the keys
		// Constructor expects (public_key, optional private_key)
		return std::make_shared<DSA>(
			SerializeKey(publicKey),
			SerializeKey(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}