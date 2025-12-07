#include <StormByte/crypto/hasher/sha256.hxx>
#include <StormByte/crypto/hasher/implementation.hxx>

#include <sha.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

using namespace StormByte::Crypto::Hasher;

bool SHA256::DoHash(std::span<const std::byte> dataSpan, WriteOnly& output) const noexcept {
	return ::Hash<CryptoPP::SHA256>(dataSpan, output);
}

Consumer SHA256::DoHash(Consumer consumer, ReadMode mode) const noexcept {
	return ::Hash<CryptoPP::SHA256>(consumer, mode);
}