/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 3
 * or later, as published by the Free Software Foundation.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#include <StormByte/crypto/implementation/secret/details.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/random.hxx>
#include <eccrypto.h>
#include <oids.h>
#include <queue.h>
#include <xed25519.h>
namespace StormByte::Crypto::Implementation::Secret {
	namespace {
		CryptoPP::OID CurveFromBits(unsigned short bits) noexcept
		{
			switch (bits) {
				case 256: return CryptoPP::ASN1::secp256r1();
				case 384: return CryptoPP::ASN1::secp384r1();
				case 521: return CryptoPP::ASN1::secp521r1();
				default:  return CryptoPP::OID();
			}
		}
		bool ExtractX25519Raw32(const CryptoPP::SecByteBlock& in,
								CryptoPP::SecByteBlock& out) noexcept
		{
			if (in.size() == 32) {
				out.Assign(in.data(), 32);
				return true;
			}

			const CryptoPP::byte* p = in.data();
			const size_t n = in.size();
			for (size_t i = 0; i + 34 <= n; ++i) {
				// OCTET STRING, length 32
				if (p[i] == 0x04 && p[i + 1] == 0x20) {
					out.Assign(p + i + 2, 32);
					return true;
				}
				// BIT STRING, length 33 (0 unused bits + 32 payload)
				if (p[i] == 0x03 && p[i + 1] == 0x21 && p[i + 2] == 0x00) {
					out.Assign(p + i + 3, 32);
					return true;
				}
				// OCTET STRING, length 34 with inner 0x04 0x20 (nested wrappers)
				if (p[i] == 0x04 && p[i + 1] == 0x22 && p[i + 2] == 0x04 && p[i + 3] == 0x20) {
					out.Assign(p + i + 4, 32);
					return true;
				}
			}
			return false;
		}
	}

	std::optional<Password> ECDHShare(const Password& privateKey,
									const std::string& peerPublicKeyBase64,
									unsigned short bits) noexcept
	{
		CryptoPP::SecByteBlock priv;
		CryptoPP::SecByteBlock pub;
		CryptoPP::SecByteBlock secret;
		try {
			const CryptoPP::OID curve = CurveFromBits(bits);
			if (curve.Empty())
				return std::nullopt;

			CryptoPP::ECDH<CryptoPP::ECP>::Domain domain(curve);

			const unsigned char* privPtr = Helpers::PasswordAccess::Data(privateKey);
			const std::size_t privLen = Helpers::PasswordAccess::Size(privateKey);
			if (!privPtr || privLen == 0)
				return std::nullopt;

			priv.Assign(privPtr, privLen);
			pub = KeyPair::DecodeSecBlockBase64(peerPublicKeyBase64);

			// Fast path: raw scalar + uncompressed point
			if (priv.size() == domain.PrivateKeyLength()
				&& pub.size() == domain.PublicKeyLength()) {
				secret.CleanNew(domain.AgreedValueLength());
				const bool ok = domain.Agree(secret, priv, pub);
				Helpers::SecureWipe(priv);
				Helpers::SecureWipe(pub);
				if (!ok) {
					Helpers::SecureWipe(secret);
					return std::nullopt;
				}
				Password out(secret.data(), secret.size());
				Helpers::SecureWipe(secret);
				return out;
			}

			// ASN.1 / SerializeKey path
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
			{
				CryptoPP::ArraySource src(privPtr, privLen, true);
				privKey.Load(src);
				if (!privKey.Validate(RNG(), 2)) {
					Helpers::SecureWipe(priv);
					Helpers::SecureWipe(pub);
					return std::nullopt;
				}
			}

			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
			{
				CryptoPP::SecByteBlock pubDer = pub;
				if (pubDer.empty()) {
					Helpers::SecureWipe(priv);
					return std::nullopt;
				}
				CryptoPP::ArraySource src(pubDer.data(), pubDer.size(), true);
				pubKey.Load(src);
				if (!pubKey.Validate(RNG(), 2)) {
					Helpers::SecureWipe(priv);
					Helpers::SecureWipe(pub);
					Helpers::SecureWipe(pubDer);
					return std::nullopt;
				}
				Helpers::SecureWipe(pubDer);
			}

			const size_t privLenRaw = domain.PrivateKeyLength();
			const size_t pubLenRaw = domain.PublicKeyLength();
			CryptoPP::SecByteBlock privRaw(privLenRaw);
			CryptoPP::SecByteBlock pubRaw(pubLenRaw);

			CryptoPP::Integer d = privKey.GetPrivateExponent();
			d.Encode(privRaw.data(), privLenRaw);

			CryptoPP::ECP::Point Q = pubKey.GetPublicElement();
			const size_t coordLen = (pubLenRaw - 1) / 2;
			pubRaw[0] = 0x04;
			Q.x.Encode(pubRaw.data() + 1, coordLen);
			Q.y.Encode(pubRaw.data() + 1 + coordLen, coordLen);

			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);

			secret.CleanNew(domain.AgreedValueLength());
			bool ok = domain.Agree(secret, privRaw, pubRaw);
			if (!ok)
				ok = domain.Agree(secret, pubRaw, privRaw);

			Helpers::SecureWipe(privRaw);
			Helpers::SecureWipe(pubRaw);

			if (!ok) {
				Helpers::SecureWipe(secret);
				return std::nullopt;
			}

			Password out(secret.data(), secret.size());
			Helpers::SecureWipe(secret);
			return out;
		} catch (...) {
			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);
			Helpers::SecureWipe(secret);
			return std::nullopt;
		}
	}

	std::optional<Password> X25519Share(const Password& privateKey,
										const std::string& peerPublicKeyBase64) noexcept
	{
		CryptoPP::SecByteBlock privIn, pubIn, priv, pub, secret;
		try {
			const unsigned char* privPtr = Helpers::PasswordAccess::Data(privateKey);
			const std::size_t privLen = Helpers::PasswordAccess::Size(privateKey);
			if (!privPtr || privLen == 0)
				return std::nullopt;

			privIn.Assign(privPtr, privLen);
			pubIn = KeyPair::DecodeSecBlockBase64(peerPublicKeyBase64);

			if (!ExtractX25519Raw32(privIn, priv) || !ExtractX25519Raw32(pubIn, pub)) {
				Helpers::SecureWipe(privIn);
				Helpers::SecureWipe(pubIn);
				return std::nullopt;
			}
			Helpers::SecureWipe(privIn);
			Helpers::SecureWipe(pubIn);

			CryptoPP::x25519 agreement;
			secret.CleanNew(agreement.AgreedValueLength());
			const bool ok = agreement.Agree(secret, priv, pub);

			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);

			if (!ok) {
				Helpers::SecureWipe(secret);
				return std::nullopt;
			}

			Password out(secret.data(), secret.size());
			Helpers::SecureWipe(secret);
			return out;
		} catch (...) {
			Helpers::SecureWipe(privIn);
			Helpers::SecureWipe(pubIn);
			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);
			Helpers::SecureWipe(secret);
			return std::nullopt;
		}
	}
}
