#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/serializable.hxx>

#include <thread>

StormByte::Buffer::Simple ReadAllFromConsumer(StormByte::Buffer::Consumer& consumer) {
	// Read the decompressed data from the decompressed_consumer
	StormByte::Buffer::Simple data;
	while (consumer.IsReadable() && !consumer.IsEoF()) {
		size_t available_bytes = consumer.AvailableBytes();
		if (available_bytes == 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			continue;
		}

		auto read_result = consumer.Read(available_bytes);
		if (!read_result.has_value()) {
			return {};
		}

		const auto& chunk = read_result.value();
		data << chunk;
	}
	return data;
}

std::string DeserializeString(const StormByte::Buffer::Simple& buffer) {
	StormByte::Buffer::Simple serialize_buffer;
	// Store Size
	serialize_buffer << buffer.Size();
	serialize_buffer << buffer;

	auto expected_string = StormByte::Serializable<std::string>::Deserialize(serialize_buffer);
	if (expected_string.has_value()) {
		return expected_string.value();
	}
	return {};
}