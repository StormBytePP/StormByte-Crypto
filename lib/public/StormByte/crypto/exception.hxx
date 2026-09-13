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
	 *
	 * Knows its own @ref StormByte::Component name (`"Crypto"`). A derived, per-component
	 * exception (@ref CompressorException, @ref CrypterException, ...) only names itself
	 * (e.g. `Component("Compressor")`) through the protected constructors below, which combine
	 * it with `"Crypto"`; it never repeats the parent's name. Anything deriving further down (a
	 * "leaf") does not name a component at all: `using Parent::Parent;` inherits the
	 * constructors already bound to the parent's combined name. The component is passed as
	 * `StormByte::Component`, never a plain string, so it can never be confused with the
	 * plain-message or format-string constructors during overload resolution.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Exception: public StormByte::Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto"` component.
			 * @param message Exception message.
			 */
			inline Exception(const std::string& message):
				StormByte::Exception(StormByte::Component("Crypto"), "{}", message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline Exception(std::format_string<Args...> fmt, Args&&... args):
				StormByte::Exception(StormByte::Component("Crypto"), fmt, std::forward<Args>(args)...) {}

		protected:
			/**
			 * @brief Combines @p component with `"Crypto"` and a plain message, for a derived exception's own constructor.
			 * @param component This derived exception's own name (e.g. `Component("Compressor")`).
			 * @param message Exception message.
			 */
			inline Exception(StormByte::Component component, const std::string& message):
				StormByte::Exception(StormByte::Component("Crypto::" + std::string(component.name)), "{}", message) {}

			/**
			 * @brief Combines @p component with `"Crypto"`, for a derived exception's own constructor.
			 * @tparam Args Format argument types.
			 * @param component This derived exception's own name (e.g. `Component("Compressor")`).
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline Exception(StormByte::Component component, std::format_string<Args...> fmt, Args&&... args):
				StormByte::Exception(StormByte::Component("Crypto::" + std::string(component.name)), fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class CompressorException
	 * @brief Exception from the compressor component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CompressorException: public Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto::Compressor"` component.
			 * @param message Exception message.
			 */
			inline CompressorException(const std::string& message):
				Exception(StormByte::Component("Compressor"), message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto::Compressor"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline CompressorException(std::format_string<Args...> fmt, Args&&... args):
				Exception(StormByte::Component("Compressor"), fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class CrypterException
	 * @brief Exception from the crypter component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC CrypterException: public Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto::Crypter"` component.
			 * @param message Exception message.
			 */
			inline CrypterException(const std::string& message):
				Exception(StormByte::Component("Crypter"), message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto::Crypter"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline CrypterException(std::format_string<Args...> fmt, Args&&... args):
				Exception(StormByte::Component("Crypter"), fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class HasherException
	 * @brief Exception from the hasher component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC HasherException: public Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto::Hasher"` component.
			 * @param message Exception message.
			 */
			inline HasherException(const std::string& message):
				Exception(StormByte::Component("Hasher"), message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto::Hasher"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline HasherException(std::format_string<Args...> fmt, Args&&... args):
				Exception(StormByte::Component("Hasher"), fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class KeyPairException
	 * @brief Exception from the keypair component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC KeyPairException: public Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto::KeyPair"` component.
			 * @param message Exception message.
			 */
			inline KeyPairException(const std::string& message):
				Exception(StormByte::Component("KeyPair"), message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto::KeyPair"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline KeyPairException(std::format_string<Args...> fmt, Args&&... args):
				Exception(StormByte::Component("KeyPair"), fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class SecretException
	 * @brief Exception from the secret component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SecretException: public Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto::Secret"` component.
			 * @param message Exception message.
			 */
			inline SecretException(const std::string& message):
				Exception(StormByte::Component("Secret"), message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto::Secret"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline SecretException(std::format_string<Args...> fmt, Args&&... args):
				Exception(StormByte::Component("Secret"), fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class SignerException
	 * @brief Exception from the signer component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SignerException: public Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto::Signer"` component.
			 * @param message Exception message.
			 */
			inline SignerException(const std::string& message):
				Exception(StormByte::Component("Signer"), message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto::Signer"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline SignerException(std::format_string<Args...> fmt, Args&&... args):
				Exception(StormByte::Component("Signer"), fmt, std::forward<Args>(args)...) {}
	};

	/**
	 * @class VaultException
	 * @brief Exception from the vault component.
	 */
	class STORMBYTE_CRYPTO_PUBLIC VaultException: public Exception {
		public:
			/**
			 * @brief Plain-message constructor, tagged with the `"Crypto::Vault"` component.
			 * @param message Exception message.
			 */
			inline VaultException(const std::string& message):
				Exception(StormByte::Component("Vault"), message) {}

			/**
			 * @brief Format-string constructor, tagged with the `"Crypto::Vault"` component.
			 * @tparam Args Format argument types.
			 * @param fmt Format string.
			 * @param args Format arguments.
			 */
			template <typename... Args>
			inline VaultException(std::format_string<Args...> fmt, Args&&... args):
				Exception(StormByte::Component("Vault"), fmt, std::forward<Args>(args)...) {}
	};
}
