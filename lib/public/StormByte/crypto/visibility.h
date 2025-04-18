#pragma once

#include <StormByte/platform.h>

#ifdef WINDOWS
	#ifdef StormByte_Crypto_EXPORTS
		#define STORMBYTE_CRYPTO_PUBLIC	__declspec(dllexport)
	#else
		#define STORMBYTE_CRYPTO_PUBLIC	__declspec(dllimport)
	#endif
	#define STORMBYTE_CRYPTO_PRIVATE
#else
	#define STORMBYTE_CRYPTO_PUBLIC		__attribute__ ((visibility ("default")))
	#define STORMBYTE_CRYPTO_PRIVATE	__attribute__ ((visibility ("default")))
#endif
