#include <StormByte/crypto/keypair/implementation.hxx>

namespace StormByte::Crypto::KeyPair {
	std::string EncodeSecBlockBase64(const CryptoPP::SecByteBlock& b) noexcept {
		std::string out;
		CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(out), false);
		enc.Put(b.data(), b.size());
		enc.MessageEnd();
		return out;
	}

	CryptoPP::SecByteBlock DecodeSecBlockBase64(const std::string& s) noexcept {
		CryptoPP::Base64Decoder dec;
		CryptoPP::StringSource ss(s, true, new CryptoPP::Redirector(dec));
		CryptoPP::SecByteBlock b;
		b.resize(dec.MaxRetrievable());
		dec.Get(b.data(), b.size());
		return b;
	}
}