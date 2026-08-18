#include <StormByte/crypto/compressor/zlib.hxx>
#include <StormByte/buffer/producer.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;

using namespace StormByte::Crypto;

int TestZlibCompressDecompressString() {
	const std::string fn_name = "TestZlibCompressDecompressString";
	const std::string input = "The quick brown fox jumps over the lazy dog.\n";

	Compressor::Zlib compressor;

	FIFO compressed_data;
	auto compressed = compressor.Compress(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()), compressed_data);
	ASSERT_TRUE(fn_name, compressed);
	ASSERT_FALSE(fn_name, compressed_data.Empty());

	FIFO decompressed_data;
	auto decompressed = compressor.Decompress(compressed_data, decompressed_data);
	ASSERT_TRUE(fn_name, decompressed);
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressed_data.Data()), input);
	RETURN_TEST(fn_name, 0);
}

int TestZlibCompressDecompressBuffer() {
	const std::string fn_name = "TestZlibCompressDecompressBuffer";
	std::string src(1024, 'A');
	StormByte::Buffer::FIFO input;
	std::vector<std::byte> bytes(src.size());
	std::transform(src.begin(), src.end(), bytes.begin(), [](char c){ return static_cast<std::byte>(c); });
	input.Write(bytes);

	Compressor::Zlib compressor;
	FIFO compressed_data;
	auto compressed = compressor.Compress(input, compressed_data);
	ASSERT_TRUE(fn_name, compressed);

	FIFO decompressed_data;
	auto decompressed = compressor.Decompress(compressed_data, decompressed_data);
	ASSERT_TRUE(fn_name, decompressed);
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressed_data.Data()), src);
	RETURN_TEST(fn_name, 0);
}

int TestZlibStreaming() {
	const std::string fn_name = "TestZlibStreaming";
	// Prepare streaming input
	std::string big(256 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>('A' + (i % 26));

	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();

	// Write in chunks to producer
	const size_t chunk = 8192;
	for (size_t off = 0; off < big.size(); off += chunk) {
		size_t n = std::min(chunk, big.size() - off);
		std::vector<std::byte> bytes(n);
		std::transform(big.begin() + off, big.begin() + off + n, bytes.begin(), [](char c){ return static_cast<std::byte>(c); });
		(void)producer.Write(bytes);
	}
	producer.Close();

	Compressor::Zlib comp;
	auto compressedConsumer = comp.Compress(consumerIn);
	// Collect compressed data from the streaming consumer robustly
	auto compressedFifo = ReadAllFromConsumer(compressedConsumer);

	// Decompress using FIFO path
	Compressor::Zlib decomp;
	FIFO decompressedFifo;
	auto decompressedFifoExp = decomp.Decompress(compressedFifo, decompressedFifo);
	ASSERT_TRUE(fn_name, decompressedFifoExp);
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressedFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int TestZlibStreamingDecompress() {
	const std::string fn_name = "TestZlibStreamingDecompress";
	std::string big(128 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));

	// Compress via span first
	Compressor::Zlib comp;
	FIFO compressedFifo;
	auto ok = comp.Compress(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(big.data()), big.size()),
		compressedFifo);
	ASSERT_TRUE(fn_name, ok);
	ASSERT_FALSE(fn_name, compressedFifo.Empty());

	// Feed compressed data as a streaming consumer
	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const auto& raw = compressedFifo.Data();
	const size_t chunk = 4096;
	for (size_t off = 0; off < raw.size(); off += chunk) {
		size_t n = std::min(chunk, raw.size() - off);
		std::vector<std::byte> bytes(raw.begin() + static_cast<std::ptrdiff_t>(off),
									raw.begin() + static_cast<std::ptrdiff_t>(off + n));
		(void)producer.Write(bytes);
	}
	producer.Close();

	Compressor::Zlib decomp;
	auto decompressedConsumer = decomp.Decompress(consumerIn);
	auto decompressedFifo = ReadAllFromConsumer(decompressedConsumer);
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressedFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int TestZlibStreamingRoundTrip() {
	const std::string fn_name = "TestZlibStreamingRoundTrip";
	std::string big(64 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('a' + (i % 26));

	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const size_t chunk = 2048;
	for (size_t off = 0; off < big.size(); off += chunk) {
		size_t n = std::min(chunk, big.size() - off);
		std::vector<std::byte> bytes(n);
		std::transform(big.begin() + static_cast<std::ptrdiff_t>(off),
					big.begin() + static_cast<std::ptrdiff_t>(off + n),
					bytes.begin(),
					[](char c) { return static_cast<std::byte>(c); });
		(void)producer.Write(bytes);
	}
	producer.Close();

	Compressor::Zlib zlib;
	auto compressedConsumer = zlib.Compress(consumerIn);
	auto decompressedConsumer = zlib.Decompress(compressedConsumer);
	auto outFifo = ReadAllFromConsumer(decompressedConsumer);
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(outFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int TestZlibEmptyInput() {
	const std::string fn_name = "TestZlibEmptyInput";
	Compressor::Zlib zlib;

	FIFO compressed;
	auto c = zlib.Compress(std::span<const std::byte>(), compressed);
	ASSERT_TRUE(fn_name, c);

	FIFO decompressed;
	auto d = zlib.Decompress(compressed, decompressed);
	ASSERT_TRUE(fn_name, d);
	ASSERT_TRUE(fn_name, decompressed.Empty() ||
				StormByte::String::FromByteVector(decompressed.Data()).empty());
	RETURN_TEST(fn_name, 0);
}

int TestZlibCompressLevelBounds() {
	const std::string fn_name = "TestZlibCompressLevelBounds";
	const std::string input = "level-bounds-test-payload";

	for (unsigned short level : {1, 5, 9}) {
		Compressor::Zlib zlib(level);
		FIFO compressed;
		ASSERT_TRUE(fn_name,
			zlib.Compress(
				std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()),
				compressed));
		FIFO decompressed;
		ASSERT_TRUE(fn_name, zlib.Decompress(compressed, decompressed));
		ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressed.Data()), input);
	}
	RETURN_TEST(fn_name, 0);
}

int main(){
	int result = 0;
	result += TestZlibCompressDecompressString();
	result += TestZlibCompressDecompressBuffer();
	result += TestZlibStreaming();
	result += TestZlibStreamingDecompress();
	result += TestZlibStreamingRoundTrip();
	result += TestZlibEmptyInput();
	result += TestZlibCompressLevelBounds();
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
