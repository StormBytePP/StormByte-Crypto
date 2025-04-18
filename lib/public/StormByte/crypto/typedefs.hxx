#pragma once

#include <StormByte/buffers/consumer.hxx>
#include <StormByte/buffers/producer.hxx>
#include <StormByte/buffers/simple.hxx>
#include <StormByte/expected.hxx>

#include <functional>
#include <future>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic related classes.
 */
namespace StormByte::Crypto {
	using FutureBuffer = std::future<Buffers::Simple>;																					///< The future data type.
	using PromisedBuffer = std::promise<Buffers::Simple>;																				///< The promised data type.
	using SharedConsumerBuffer = std::shared_ptr<Buffers::Consumer>;																	///< The shared consumer buffer type.
	using SharedProducerBuffer = std::shared_ptr<Buffers::Producer>;																	///< The shared producer buffer type.
}