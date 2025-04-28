#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/buffer/producer.hxx>
#include <StormByte/buffer/simple.hxx>
#include <StormByte/expected.hxx>

#include <functional>
#include <future>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic related classes.
 */
namespace StormByte::Crypto {
	using FutureBuffer = std::future<Buffer::Simple>;																					///< The future data type.
	using PromisedBuffer = std::promise<Buffer::Simple>;																				///< The promised data type.
	using SharedConsumerBuffer = std::shared_ptr<Buffer::Consumer>;																	///< The shared consumer buffer type.
	using SharedProducerBuffer = std::shared_ptr<Buffer::Producer>;																	///< The shared producer buffer type.
}