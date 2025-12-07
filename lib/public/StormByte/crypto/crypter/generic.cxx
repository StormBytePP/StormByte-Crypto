#include <StormByte/crypto/crypter/generic.hxx>

using namespace StormByte::Crypto::Crypter;

bool Generic::DoEncrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);

	if (!read_ok)
		return false;
	
	return DoEncrypt(std::span<const std::byte>(data.data(), data.size()), output);
}

bool Generic::DoDecrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);

	if (!read_ok)
		return false;
	
	return DoDecrypt(std::span<const std::byte>(data.data(), data.size()), output);	
}

