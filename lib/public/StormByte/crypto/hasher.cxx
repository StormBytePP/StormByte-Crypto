#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher.hxx>
#include <StormByte/crypto/implementation/hash/blake2b.hxx>
#include <StormByte/crypto/implementation/hash/blake2s.hxx>
#include <StormByte/crypto/implementation/hash/sha256.hxx>
#include <StormByte/crypto/implementation/hash/sha512.hxx>

using namespace StormByte::Crypto;

Hasher::Hasher(const Algorithm::Hash& algorithm) noexcept
:m_algorithm(algorithm) {}

StormByte::Expected<std::string, Exception> Hasher::Hash(const std::string& input) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Hash::Blake2b:
			return Implementation::Hash::Blake2b::Hash(input);
		case Algorithm::Hash::Blake2s:
			return Implementation::Hash::Blake2s::Hash(input);
		case Algorithm::Hash::SHA256:
			return Implementation::Hash::SHA256::Hash(input);
		case Algorithm::Hash::SHA512:
			return Implementation::Hash::SHA512::Hash(input);
		default:
			return input;
	}
}

StormByte::Expected<std::string, Exception> Hasher::Hash(const Buffer::FIFO& buffer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Hash::Blake2b:
			return Implementation::Hash::Blake2b::Hash(buffer);
		case Algorithm::Hash::Blake2s:
			return Implementation::Hash::Blake2s::Hash(buffer);
		case Algorithm::Hash::SHA256:
			return Implementation::Hash::SHA256::Hash(buffer);
		case Algorithm::Hash::SHA512:
			return Implementation::Hash::SHA512::Hash(buffer);
		default: {
			auto data = const_cast<Buffer::FIFO&>(buffer).Extract(0);
			if (!data.has_value()) {
				return StormByte::Unexpected<Exception>("Failed to extract data from buffer");
			}
			return std::string(reinterpret_cast<const char*>(data.value().data()), data.value().size());
		}
	}
}

StormByte::Buffer::Consumer Hasher::Hash(const Buffer::Consumer consumer) const noexcept {
	switch(m_algorithm) {
		case Algorithm::Hash::Blake2b:
			return Implementation::Hash::Blake2b::Hash(consumer);
		case Algorithm::Hash::Blake2s:
			return Implementation::Hash::Blake2s::Hash(consumer);
		case Algorithm::Hash::SHA256:
			return Implementation::Hash::SHA256::Hash(consumer);
		case Algorithm::Hash::SHA512:
			return Implementation::Hash::SHA512::Hash(consumer);
		default:
			return consumer;
	}
}