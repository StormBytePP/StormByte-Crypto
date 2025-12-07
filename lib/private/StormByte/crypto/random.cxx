#include <StormByte/crypto/random.hxx>

namespace StormByte::Crypto {
	CryptoPP::AutoSeededRandomPool& RNG() {
		static CryptoPP::AutoSeededRandomPool rngInstance;
		return rngInstance;
	}
}