#include <StormByte/crypto/hasher/blake2s.hxx>
#include <StormByte/crypto/hasher/implementation.hxx>

#include <blake2.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

using namespace StormByte::Crypto::Hasher;

bool Blake2s::DoHash(std::span<const std::byte> dataSpan, WriteOnly& output) const noexcept {
	return ::Hash<CryptoPP::BLAKE2s>(dataSpan, output);
}

Consumer Blake2s::DoHash(Consumer consumer, ReadMode mode) const noexcept {
	return ::Hash<CryptoPP::BLAKE2s>(consumer, mode);
}