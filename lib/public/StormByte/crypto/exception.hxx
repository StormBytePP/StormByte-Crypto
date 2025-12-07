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
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			Exception(const std::string& component, std::format_string<Args...> fmt, Args&&... args):
				StormByte::Exception("Crypto::" + component, fmt, std::forward<Args>(args)...) {}

			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using StormByte::Exception::Exception;
	};

	/**
	 * @class CompressorException
	 * @brief A class representing an exception in the compressor component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CompressorException: public Exception {
		public:
			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			CompressorException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Compressor: ", fmt, std::forward<Args>(args)...) {}

			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using Exception::Exception;
	};

	/**
	 * @class CrypterException
	 * @brief A class representing an exception in the crypter component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CrypterException: public Exception {
		public:
			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			CrypterException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Crypter: ", fmt, std::forward<Args>(args)...) {}

			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using Exception::Exception;
	};

	/**
	 * @class HasherException
	 * @brief A class representing an exception in the hasher component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC HasherException: public Exception {
		public:
			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			HasherException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Hasher: ", fmt, std::forward<Args>(args)...) {}

			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using Exception::Exception;
	};

	/**
	 * @class KeyPairException
	 * @brief A class representing an exception in the keypair component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC KeyPairException: public Exception {
		public:
			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			KeyPairException(std::format_string<Args...> fmt, Args&&... args):
				Exception("KeyPair: ", fmt, std::forward<Args>(args)...) {}

			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using Exception::Exception;
	};

	/**
	 * @class SecretException
	 * @brief A class representing an exception in the secret component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SecretException: public Exception {
		public:
			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			SecretException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Secret: ", fmt, std::forward<Args>(args)...) {}

			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using Exception::Exception;
	};

	/**
	 * @class SignerException
	 * @brief A class representing an exception in the signer component of the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SignerException: public Exception {
		public:
			/**
			 * @brief Constructor
			 * @param component The component where the exception occurred.
			 * @param fmt The format string for the exception message.
			 * @param args The arguments for the format string.
			 */
			template <typename... Args>
			SignerException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Signer: ", fmt, std::forward<Args>(args)...) {}

			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using Exception::Exception;
	};
}