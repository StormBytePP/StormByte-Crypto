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

#pragma once

#include <StormByte/crypto/visibility.h>
#include <StormByte/exception.hxx>

/**
 * @brief Crypto module of the StormByte suite.
 */
namespace StormByte::Crypto {
	/**
	 * @class Exception
	 * @brief Base exception for the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Exception: public StormByte::Exception {
		public:
			/**
			 * @brief Constructor.
			 * @param message Exception message.
			 */
			inline Exception(const std::string& message):
				StormByte::Exception("Crypto", message) {}

			/**
			 * @brief Constructor with a component prefix and a format string.
			 * @param component Component where the exception occurred.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline Exception(const std::string& component, std::format_string<Args...> fmt, Args&&... args):
				StormByte::Exception("Crypto::" + component, fmt, std::forward<Args>(args)...) {}

			// Intentionally do not inherit base constructors to avoid MSVC overload ambiguities
	};

	/**
	 * @class CompressorException
	 * @brief Exception from the compressor component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CompressorException: public Exception {
		public:
			/**
			 * @brief Plain-string constructor (avoids MSVC overload ambiguity with `const char*`).
			 * @param message Exception message.
			 */
			inline CompressorException(const std::string& message): Exception(std::string("Compressor: ") + message) {}

			/**
			 * @brief Format-string constructor.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline CompressorException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Compressor: ", fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class CrypterException
	 * @brief Exception from the crypter component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CrypterException: public Exception {
		public:
			/**
			 * @brief Plain-string constructor.
			 * @param message Exception message.
			 */
			inline CrypterException(const std::string& message): Exception(std::string("Crypter: ") + message) {}

			/**
			 * @brief Format-string constructor.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline CrypterException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Crypter: ", fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class HasherException
	 * @brief Exception from the hasher component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC HasherException: public Exception {
		public:
			/**
			 * @brief Plain-string constructor.
			 * @param message Exception message.
			 */
			inline HasherException(const std::string& message): Exception(std::string("Hasher: ") + message) {}

			/**
			 * @brief Format-string constructor.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline HasherException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Hasher: ", fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class KeyPairException
	 * @brief Exception from the keypair component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC KeyPairException: public Exception {
		public:
			/**
			 * @brief Plain-string constructor.
			 * @param message Exception message.
			 */
			inline KeyPairException(const std::string& message): Exception(std::string("KeyPair: ") + message) {}

			/**
			 * @brief Format-string constructor.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline KeyPairException(std::format_string<Args...> fmt, Args&&... args):
				Exception("KeyPair: ", fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class SecretException
	 * @brief Exception from the secret component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SecretException: public Exception {
		public:
			/**
			 * @brief Plain-string constructor.
			 * @param message Exception message.
			 */
			inline SecretException(const std::string& message): Exception(std::string("Secret: ") + message) {}

			/**
			 * @brief Format-string constructor.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline SecretException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Secret: ", fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class SignerException
	 * @brief Exception from the signer component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SignerException: public Exception {
		public:
			/**
			 * @brief Plain-string constructor.
			 * @param message Exception message.
			 */
			inline SignerException(const std::string& message): Exception(std::string("Signer: ") + message) {}

			/**
			 * @brief Format-string constructor.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline SignerException(std::format_string<Args...> fmt, Args&&... args):
				Exception("Signer: ", fmt, std::forward<Args>(args)...) {}
	};
}
