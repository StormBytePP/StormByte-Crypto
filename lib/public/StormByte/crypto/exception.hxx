#pragma once

#include <StormByte/crypto/visibility.h>
#include <StormByte/exception.hxx>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Exception
	 * @brief A class representing an exception in the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Exception: public StormByte::Exception {
		public:
			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			inline Exception(const std::string& message):
				StormByte::Exception("Crypto", message) {}

			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			inline Exception(const std::string& component, std::format_string<Args...> fmt, Args&&... args):
				StormByte::Exception("Crypto::" + component, fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};

	/**
	 * @class CompressorException
	 * @brief A class representing an exception in the compressor component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CompressorException: public Exception {
		public:
			/**
			 * @brief Non-templated constructor for plain string messages.
			 * This resolves MSVC overload ambiguities when passing `const char*` or `std::string`.
			 */
			inline CompressorException(const std::string& message): Exception(std::string("Compressor: ") + message) {}

			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			inline CompressorException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Compressor: ", fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};

	/**
	 * @class CrypterException
	 * @brief A class representing an exception in the crypter component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CrypterException: public Exception {
		public:
			/**
			 * @brief Non-templated constructor for plain string messages.
			 * This resolves MSVC overload ambiguities when passing `const char*` or `std::string`.
			 */
			inline CrypterException(const std::string& message): Exception(std::string("Crypter: ") + message) {}

			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			inline CrypterException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Crypter: ", fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};

	/**
	 * @class HasherException
	 * @brief A class representing an exception in the hasher component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC HasherException: public Exception {
		public:
			/**
			 * @brief Non-templated constructor for plain string messages.
			 * This resolves MSVC overload ambiguities when passing `const char*` or `std::string`.
			 */
			inline HasherException(const std::string& message): Exception(std::string("Hasher: ") + message) {}

			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			inline HasherException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Hasher: ", fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};

	/**
	 * @class KeyPairException
	 * @brief A class representing an exception in the keypair component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC KeyPairException: public Exception {
		public:
			/**
			 * @brief Non-templated constructor for plain string messages.
			 * This resolves MSVC overload ambiguities when passing `const char*` or `std::string`.
			 */
			inline KeyPairException(const std::string& message): Exception(std::string("KeyPair: ") + message) {}

			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			inline KeyPairException(std::format_string<Args...> fmt, Args&&... args):
				Exception("KeyPair: ", fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};

	/**
	 * @class SecretException
	 * @brief A class representing an exception in the secret component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SecretException: public Exception {
		public:
			/**
			 * @brief Non-templated constructor for plain string messages.
			 * This resolves MSVC overload ambiguities when passing `const char*` or `std::string`.
			 */
			inline SecretException(const std::string& message): Exception(std::string("Secret: ") + message) {}

			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			inline SecretException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Secret: ", fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};

	/**
	 * @class SignerException
	 * @brief A class representing an exception in the signer component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SignerException: public Exception {
		public:
			/**
			 * @brief Non-templated constructor for plain string messages.
			 * This resolves MSVC overload ambiguities when passing `const char*` or `std::string`.
			 */
			inline SignerException(const std::string& message): Exception(std::string("Signer: ") + message) {}

			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			inline SignerException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Signer: ", fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};
}