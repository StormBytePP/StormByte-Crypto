#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher.hxx>
#include <StormByte/crypto/implementation/hash/blake2b.hxx>
#include <StormByte/crypto/implementation/hash/blake2s.hxx>
#include <StormByte/crypto/implementation/hash/sha256.hxx>
#include <StormByte/crypto/implementation/hash/sha512.hxx>
#include <StormByte/crypto/implementation/hash/sha3.hxx>

using StormByte::Buffer::DataType;
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
		case Algorithm::Hash::SHA3_256:
			return Implementation::Hash::SHA3_256::Hash(input);
		case Algorithm::Hash::SHA3_512:
			return Implementation::Hash::SHA3_512::Hash(input);
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
		case Algorithm::Hash::SHA3_256:
			return Implementation::Hash::SHA3_256::Hash(buffer);
		case Algorithm::Hash::SHA3_512:
			return Implementation::Hash::SHA3_512::Hash(buffer);
		default: {
			DataType data;
			auto read_ok = buffer.Read(data);
			if (!read_ok.has_value()) {
				return Unexpected(HasherException("Failed to extract data from buffer"));
			}
			return std::string(reinterpret_cast<const char*>(data.data()), data.size());
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
		case Algorithm::Hash::SHA3_256:
			return Implementation::Hash::SHA3_256::Hash(consumer);
		case Algorithm::Hash::SHA3_512:
			return Implementation::Hash::SHA3_512::Hash(consumer);
		default:
			return consumer;
	}
}