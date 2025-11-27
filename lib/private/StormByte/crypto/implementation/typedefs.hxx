#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/buffer/producer.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/expected.hxx>

#include <functional>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic related classes.
 */
namespace StormByte::Crypto {
	using SharedConsumerBuffer = std::shared_ptr<Buffer::Consumer>;		///< The shared consumer buffer type.
	using SharedProducerBuffer = std::shared_ptr<Buffer::Producer>;		///< The shared producer buffer type.
}