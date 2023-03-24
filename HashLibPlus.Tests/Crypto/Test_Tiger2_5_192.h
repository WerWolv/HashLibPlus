#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace CryptoHashTests
{
	TEST_CASE("Tiger2_5_192Tests")
	{
		std::string HashOfEmptyData = "61C657CC0C3C147ED90779B36A1E811F1D27F406E3F37010";
		std::string HashOfDefaultData = "7F71F95B346733E7022D4B85BDA9C51E904825F73AF0E8AE";
		std::string HashOfOnetoNine = "F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED1440C213";
		std::string HashOfABCDE = "14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177B4ADF2A8";
		std::string HashOfDefaultDataWithHMACWithLongKey = "0DEC75166CD4CFF2A564373827255CDAF7A278CCF2143ED4";
		std::string HashOfDefaultDataWithHMACWithShortKey = "19AD11BA8D3534C41CAA2A9DAA80958EDCDB0B67FF3BF55D";
		
		IHash HashInstance = HashFactory::Crypto::CreateTiger2_5_192();
		IHMACNotBuildIn HMACInstance = HashFactory::HMAC::CreateHMAC(HashInstance);

		SECTION("HMACWithDefaultDataAndLongKey")
		{
			IHMACNotBuildIn hmac = HashFactory::HMAC::CreateHMAC(HashInstance);
			hmac->SetKey(HMACLongKeyBytes);

			std::string String = HashOfDefaultDataWithHMACWithLongKey;
			std::string ActualString = hmac->ComputeString(DefaultData)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("HMACWithDefaultDataAndShortKey")
		{
			IHMACNotBuildIn hmac = HashFactory::HMAC::CreateHMAC(HashInstance);
			hmac->SetKey(HMACShortKeyBytes);

			std::string String = HashOfDefaultDataWithHMACWithShortKey;
			std::string ActualString = hmac->ComputeString(DefaultData)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestEmptyString")
		{
			std::string String = HashOfEmptyData;
			std::string ActualString = HashInstance->ComputeString(EmptyData)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestDefaultData")
		{
			std::string String = HashOfDefaultData;
			std::string ActualString = HashInstance->ComputeString(DefaultData)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestOnetoNine")
		{
			std::string String = HashOfOnetoNine;
			std::string ActualString = HashInstance->ComputeString(OneToNine)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestBytesABCDE")
		{
			std::string String = HashOfABCDE;
			std::string ActualString = HashInstance->ComputeBytes(BytesABCDE)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestEmptyStream")
		{
			// Read empty file to stream
			std::ifstream stream("EmptyFile.txt");

			std::string String = HashOfEmptyData;
			std::string ActualString = HashInstance->ComputeStream(stream)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestIncrementalHash")
		{
			HashInstance->Initialize();
			HashInstance->TransformString(DefaultData.substr(0, 3));
			HashInstance->TransformString(DefaultData.substr(3, 3));
			HashInstance->TransformString(DefaultData.substr(6, 3));
			HashInstance->TransformString(DefaultData.substr(9, 3));
			HashInstance->TransformString(DefaultData.substr(12));

			std::string String = HashOfDefaultData;
			std::string ActualString = HashInstance->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestIndexChunkedDataIncrementalHash")
		{
			Int32 Count, i;
			HashLibByteArray temp, ChunkedDataBytes;
			IHash HashInstanceCopy = nullptr;

			HashInstanceCopy = HashInstance->Clone();
			ChunkedDataBytes = Converters::ConvertStringToBytes(ChunkedData);
			for (i = 0; i < (Int32)ChunkedDataBytes.size(); i++)
			{
				Count = (Int32)ChunkedDataBytes.size() - i;

				const HashLibByteArray::const_iterator start = ChunkedDataBytes.begin() + i;
				const HashLibByteArray::const_iterator end = ChunkedDataBytes.end();

				temp = HashLibByteArray(start, end);
				HashInstance->Initialize();

				HashInstance->TransformBytes(ChunkedDataBytes, i, Count);

				std::string ActualString = HashInstance->TransformFinal()->ToString();
				std::string String = HashInstanceCopy->ComputeBytes(temp)->ToString();

				REQUIRE(String == ActualString);
			}
		}

		SECTION("TestAnotherChunkedDataIncrementalHash")
		{
			size_t x, size, i;
			std::string temp;
			IHash HashInstanceCopy = nullptr;

			HashInstanceCopy = HashInstance->Clone();
			for (x = 0; x < (sizeof(ChunkSizes) / sizeof(Int32)); x++)
			{
				size = ChunkSizes[x];
				HashInstance->Initialize();
				i = size;
				while (i < ChunkedData.size())
				{
					temp = ChunkedData.substr((i - size), size);
					HashInstance->TransformString(temp);

					i += size;
				}

				temp = ChunkedData.substr((i - size), ChunkedData.size() - ((i - size)));
				HashInstance->TransformString(temp);

				std::string ActualString = HashInstance->TransformFinal()->ToString();
				std::string String = HashInstanceCopy->ComputeString(ChunkedData)->ToString();

				REQUIRE(String == ActualString);
			}
		}

		SECTION("TestHashCloneIsCorrect")
		{
			IHash Original = HashInstance->Clone();
			IHash Copy;

			// Initialize Original Hash
			Original->Initialize();
			Original->TransformBytes(ChunkOne);

			// Make Copy Of Current State
			Copy = Original->Clone();

			Original->TransformBytes(ChunkTwo);
			std::string String = Original->TransformFinal()->ToString();

			Copy->TransformBytes(ChunkTwo);
			std::string ActualString = Copy->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestHashCloneIsUnique")
		{
			IHash Original = HashInstance->Clone();
			IHash Copy;

			Original->Initialize();
			Original->SetBufferSize(64 * 1024); // 64Kb
												// Make Copy Of Current State

			Copy = Original->Clone();
			Copy->SetBufferSize(128 * 1024); // 128Kb

			REQUIRE_FALSE(Original->GetBufferSize() == Copy->GetBufferSize());
		}

		SECTION("TestHMACCloneIsCorrect")
		{
			IHMACNotBuildIn Original;
			IHMACNotBuildIn Copy;

			Original = HashFactory::HMAC::CreateHMAC(HashInstance);
			Original->SetKey(HMACLongKeyBytes);
			Original->Initialize();
			Original->TransformBytes(ChunkOne);

			// Make Copy Of Current State
			Copy = Original->CloneHMAC();

			Original->TransformBytes(ChunkTwo);
			std::string String = Original->TransformFinal()->ToString();

			Copy->TransformBytes(ChunkTwo);
			std::string ActualString = Copy->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

	};


}