#include <StormByte/crypto/implementation/keypair/details.hxx>

#include <base64.h>
#include <filters.h>

namespace StormByte::Crypto::Implementation::KeyPair {
	std::string EncodeSecBlockBase64(const CryptoPP::SecByteBlock& b) noexcept
	{
		std::string out;
		CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(out), false);
		enc.Put(b.data(), b.size());
		enc.MessageEnd();
		return out;
	}

	CryptoPP::SecByteBlock DecodeSecBlockBase64(const std::string& s) noexcept
	{
		CryptoPP::Base64Decoder dec;
		CryptoPP::StringSource ss(s, true, new CryptoPP::Redirector(dec));
		CryptoPP::SecByteBlock b;
		b.resize(dec.MaxRetrievable());
		if (b.size() > 0)
			dec.Get(b.data(), b.size());
		return b;
	}
}
