#include <StormByte/crypto/compressor.hxx>
#include <StormByte/buffer/producer.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

using namespace StormByte::Crypto;

int TestZlibCompressDecompressString() {
	const std::string fn_name = "TestZlibCompressDecompressString";
	const std::string input = "The quick brown fox jumps over the lazy dog.\n";

	Compressor compressor(Algorithm::Compress::Zlib);
	auto compressed = compressor.Compress(input);
	ASSERT_TRUE(fn_name, compressed.has_value());
	ASSERT_TRUE(fn_name, !compressed->empty());

	auto decompressed = compressor.Decompress(compressed.value());
	ASSERT_TRUE(fn_name, decompressed.has_value());
	ASSERT_TRUE(fn_name, decompressed.value() == input);
	RETURN_TEST(fn_name, 0);
}

int TestZlibCompressDecompressBuffer() {
	const std::string fn_name = "TestZlibCompressDecompressBuffer";
	std::string src(1024, 'A');
	StormByte::Buffer::FIFO input;
	std::vector<std::byte> bytes(src.size());
	std::transform(src.begin(), src.end(), bytes.begin(), [](char c){ return static_cast<std::byte>(c); });
	(void)input.Write(bytes);

	Compressor compressor(Algorithm::Compress::Zlib);
	auto compressed = compressor.Compress(input);
	ASSERT_TRUE(fn_name, compressed.has_value());

	auto decompressed = compressor.Decompress(compressed.value());
	ASSERT_TRUE(fn_name, decompressed.has_value());
	auto data = decompressed->Extract(0);
	ASSERT_TRUE(fn_name, data.has_value());
	std::string out(reinterpret_cast<const char*>(data->data()), data->size());
	ASSERT_TRUE(fn_name, out == src);
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

	Compressor comp(Algorithm::Compress::Zlib);
	auto compressedConsumer = comp.Compress(consumerIn);
	// Collect compressed data from the streaming consumer robustly
	auto compressedFifo = ReadAllFromConsumer(compressedConsumer);

	// Decompress using FIFO path
	Compressor decomp(Algorithm::Compress::Zlib);
	auto decompressedFifoExp = decomp.Decompress(compressedFifo);
	ASSERT_TRUE(fn_name, decompressedFifoExp.has_value());
	auto& fifo = decompressedFifoExp.value();
	auto data = fifo.Extract(0);
	ASSERT_TRUE(fn_name, data.has_value());
	std::string out(reinterpret_cast<const char*>(data->data()), data->size());
	ASSERT_TRUE(fn_name, out == big);
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
