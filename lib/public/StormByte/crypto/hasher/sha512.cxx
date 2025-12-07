#include <StormByte/crypto/hasher/sha512.hxx>
#include <StormByte/crypto/hasher/implementation.hxx>

#include <sha.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

using namespace StormByte::Crypto::Hasher;

bool SHA512::DoHash(std::span<const std::byte> dataSpan, WriteOnly& output) const noexcept {
	return ::Hash<CryptoPP::SHA512>(dataSpan, output);
}

Consumer SHA512::DoHash(Consumer consumer, ReadMode mode) const noexcept {
	return ::Hash<CryptoPP::SHA512>(consumer, mode);
}