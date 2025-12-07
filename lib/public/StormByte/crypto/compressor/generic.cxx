#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/crypto/compressor/zlib.hxx>

using namespace StormByte::Crypto::Compressor;

bool Generic::DoCompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);

	if (!read_ok)
		return false;
	
	return DoCompress(std::span<const std::byte>(data.data(), data.size()), output);
}

bool Generic::DoDecompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);

	if (!read_ok)
		return false;
	
	return DoDecompress(std::span<const std::byte>(data.data(), data.size()), output);	
}

namespace StormByte::Crypto::Compressor {
	/**
	 * @brief Factory method to create a Generic compressor.
	 * @param type The type of compressor to create.
	 * @param level The compression level.
	 * @return A pointer to the created Generic compressor.
	 */
	Generic::PointerType Create(Type type, unsigned short level) noexcept {
		switch (type) {
			case Type::Bzip2:
				return std::make_shared<Bzip2>(level);
			case Type::Zlib:
				return std::make_shared<Zlib>(level);
			default:
				return nullptr;
		}
	}
}