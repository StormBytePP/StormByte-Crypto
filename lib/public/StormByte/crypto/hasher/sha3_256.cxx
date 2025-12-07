#include <StormByte/crypto/hasher/sha3_256.hxx>
#include <StormByte/crypto/hasher/implementation.hxx>

#include <sha3.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

using namespace StormByte::Crypto::Hasher;

bool SHA3_256::DoHash(std::span<const std::byte> dataSpan, WriteOnly& output) const noexcept {
	return ::Hash<CryptoPP::SHA3_256>(dataSpan, output);
}

Consumer SHA3_256::DoHash(Consumer consumer, ReadMode mode) const noexcept {
	return ::Hash<CryptoPP::SHA3_256>(consumer, mode);
}