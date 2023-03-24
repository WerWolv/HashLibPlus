#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace CryptoHashTests
{
	TEST_CASE("SHA2_224Tests")
	{
		std::string HashOfEmptyData = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
		std::string HashOfDefaultData = "DF2B86ED008508F542443C4B1810AA5A0F5658692B808EEB1D0A2F7E";
		std::string HashOfDefaultDataWithHMACWithLongKey = "369B2FAF691265B647E13F7A46223816A93CF7885956C9855729D511";
		std::string HashOfDefaultDataWithHMACWithShortKey = "EC47E83DB5DD735EBB7AA4A898460950B16A3A0FA48E4BB9184EA3D1";
		std::string HashOfOnetoNine = "9B3E61BF29F17C75572FAE2E86E17809A4513D07C8A18152ACF34521";
		std::string HashOfABCDE = "BDD03D560993E675516BA5A50638B6531AC2AC3D5847C61916CFCED6";

		IHash HashInstance = HashFactory::Crypto::CreateSHA2_224();
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