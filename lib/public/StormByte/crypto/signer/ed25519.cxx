#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/implementation/signer/details.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/random.hxx>

#include <xed25519.h>
#include <filters.h>
#include <queue.h>

#include <memory>

using StormByte::Buffer::DataType;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Crypto::Helpers::PasswordAccess;
using StormByte::Crypto::Helpers::SecureWipe;

namespace {
    struct Ed25519SignBox final : StormByte::Crypto::Implementation::Signer::SignBox {
        CryptoPP::ed25519::Signer signer;
        DataType signature;
        std::unique_ptr<CryptoPP::SignerFilter> filter;
        bool ready = false;

        explicit Ed25519SignBox(const StormByte::Crypto::Password& priv)
        {
            const unsigned char* privData = PasswordAccess::Data(priv);
            const std::size_t privSize = PasswordAccess::Size(priv);
            if (!privData || privSize == 0)
                return;

            CryptoPP::ByteQueue queue;
            queue.Put(privData, privSize);
            signer.AccessPrivateKey().Load(queue);

            filter = std::make_unique<CryptoPP::SignerFilter>(
                StormByte::Crypto::RNG(),
                signer,
                new CryptoPP::StringSinkTemplate<DataType>(signature)
            );
            ready = true;
        }

        bool Update(std::span<const std::byte> in) override
        {
            if (!ready || !filter)
                return false;
            try {
                filter->Put(
                    reinterpret_cast<const CryptoPP::byte*>(in.data()),
                    in.size_bytes());
                return true;
            } catch (...) {
                return false;
            }
        }

        bool Finalize(DataType& out) override
        {
            if (!ready || !filter)
                return false;
            try {
                filter->MessageEnd();
                out = std::move(signature);
                filter.reset();
                return true;
            } catch (...) {
                return false;
            }
        }
    };

    struct Ed25519VerifyBox final : StormByte::Crypto::Implementation::Signer::VerifyBox {
        CryptoPP::ed25519::Verifier verifier;
        bool result = false;
        std::unique_ptr<CryptoPP::SignatureVerificationFilter> filter;
        bool ready = false;

        explicit Ed25519VerifyBox(const std::string& pubKeyB64)
        {
            CryptoPP::SecByteBlock pubRaw =
                StormByte::Crypto::Implementation::KeyPair::DecodeSecBlockBase64(pubKeyB64);
            CryptoPP::ByteQueue queue;
            queue.Put(pubRaw.data(), pubRaw.size());
            SecureWipe(pubRaw);

            verifier.AccessPublicKey().Load(queue);
            ready = true;
        }

        bool Begin(const std::string& signature) override
        {
            if (!ready)
                return false;
            try {
                filter = std::make_unique<CryptoPP::SignatureVerificationFilter>(
                    verifier,
                    new CryptoPP::ArraySink(
                        reinterpret_cast<CryptoPP::byte*>(&result),
                        sizeof(result)),
                    CryptoPP::SignatureVerificationFilter::PUT_RESULT |
                        CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
                );
                filter->Put(
                    reinterpret_cast<const CryptoPP::byte*>(signature.data()),
                    signature.size());
                return true;
            } catch (...) {
                return false;
            }
        }

        bool Update(std::span<const std::byte> in) override
        {
            if (!filter)
                return false;
            try {
                filter->Put(
                    reinterpret_cast<const CryptoPP::byte*>(in.data()),
                    in.size_bytes());
                return true;
            } catch (...) {
                return false;
            }
        }

        bool Finalize() override
        {
            if (!filter)
                return false;
            try {
                filter->MessageEnd();
                filter.reset();
                return result;
            } catch (...) {
                return false;
            }
        }
    };

} // namespace

namespace StormByte::Crypto::Signer {

    bool ED25519::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept
    {
        if (!m_keypair || !m_keypair->HasPrivateKey())
            return false;

        return Implementation::Signer::SignSpan(
            data, output,
            std::make_unique<Ed25519SignBox>(*m_keypair->PrivateKey()));
    }

    Consumer ED25519::DoSign(Consumer consumer, ReadMode mode) const noexcept
    {
        if (!m_keypair || !m_keypair->HasPrivateKey()) {
            Producer producer;
            producer.SetError();
            return producer.Consumer();
        }

        return Implementation::Signer::SignStream(
            std::move(consumer), mode,
            std::make_unique<Ed25519SignBox>(*m_keypair->PrivateKey()));
    }

    bool ED25519::DoVerify(std::span<const std::byte> data,
                           const std::string& signature) const noexcept
    {
        if (!m_keypair)
            return false;

        return Implementation::Signer::VerifySpan(
            data, signature,
            std::make_unique<Ed25519VerifyBox>(m_keypair->PublicKey()));
    }

    bool ED25519::DoVerify(Consumer consumer,
                           const std::string& signature,
                           ReadMode mode) const noexcept
    {
        if (!m_keypair)
            return false;

        return Implementation::Signer::VerifyStream(
            std::move(consumer), mode, signature,
            std::make_unique<Ed25519VerifyBox>(m_keypair->PublicKey()));
    }
}
