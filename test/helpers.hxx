#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/string.hxx>

#include <thread>

using StormByte::Buffer::DataType;

StormByte::Buffer::FIFO ReadAllFromConsumer(StormByte::Buffer::Consumer consumer) {
	// Read the decompressed data from the consumer
	StormByte::Buffer::FIFO data;
	while (!consumer.EoF()) {
		size_t available_bytes = consumer.AvailableBytes();
		if (available_bytes == 0) {
			std::this_thread::yield();
			continue;
		}

		DataType d;
		auto read_result = consumer.Read(available_bytes, d);
		if (!read_result.has_value()) {
			return data;
		}

		(void)data.Write(std::move(d));
	}
	return data;
}

std::string DeserializeString(const StormByte::Buffer::FIFO& buffer) {
	DataType data;
	auto read_ok = buffer.Read(data);
	if (!read_ok.has_value()) {
		return {};
	}

	return StormByte::String::FromByteVector(data);
}