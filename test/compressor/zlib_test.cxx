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

int main(){
	int result = 0;
	result += TestZlibCompressDecompressString();
	result += TestZlibCompressDecompressBuffer();
	result += TestZlibStreaming();
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
