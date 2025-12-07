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
		bool read_result = consumer.Read(available_bytes, d);
		if (!read_result) {
			std::cerr << "ReadAllFromConsumer: Read returned false, available=" << available_bytes << " EoF=" << consumer.EoF() << " writable=" << consumer.IsWritable() << std::endl;
			return data;
		}
		if (d.empty()) {
			std::cerr << "ReadAllFromConsumer: read zero bytes despite available=" << available_bytes << std::endl;
		}

		data.Write(std::move(d));
	}
	return data;
}

std::string DeserializeString(const StormByte::Buffer::FIFO& buffer) {
	DataType data;
	bool read_ok = buffer.Read(data);
	if (!read_ok) {
		return {};
	}

	return StormByte::String::FromByteVector(data);
}

// Overload: accept a raw DataType (vector<std::byte>) directly and convert
// to a std::string. Some call sites pass `fifo.Data()` which returns the
// internal `DataType` reference; providing this overload avoids an implicit
// conversion to `FIFO` and is more direct.
inline std::string DeserializeString(const DataType& data) {
	return StormByte::String::FromByteVector(data);
}