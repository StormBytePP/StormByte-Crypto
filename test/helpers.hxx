#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/string.hxx>

#include <thread>

StormByte::Buffer::FIFO ReadAllFromConsumer(StormByte::Buffer::Consumer consumer) {
	// Read the decompressed data from the consumer
	StormByte::Buffer::FIFO data;
	while (consumer.IsWritable() || !consumer.Empty()) {
		size_t available_bytes = consumer.AvailableBytes();
		if (available_bytes == 0) {
			if (!consumer.IsWritable()) {
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			continue;
		}

		auto read_result = consumer.Read(available_bytes);
		if (!read_result.has_value()) {
			return data;
		}

		const auto& chunk = read_result.value();
		data.Write(chunk);
	}
	return data;
}

std::string DeserializeString(const StormByte::Buffer::FIFO& buffer) {
	auto data = const_cast<StormByte::Buffer::FIFO&>(buffer).Extract();
	if (!data.has_value()) {
		return {};
	}

	return StormByte::String::FromByteVector(data.value());
}