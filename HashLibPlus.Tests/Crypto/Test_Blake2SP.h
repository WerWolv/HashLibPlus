#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake2STestVectors.h"

namespace CryptoHashTests
{
	TEST_CASE("Blake2SPTests")
	{
		std::string HashOfEmptyData = "DD0E891776933F43C7D032B08A917E25741F8AA9A12C12E1CAC8801500F2CA4F";
		std::string HashOfDefaultData = "F1617895134C203ED0A9C8CC72938161EBC9AB6F233BBD3CCFC4D4BCA08A5ED0";
		std::string HashOfOnetoNine = "D6D3157BD4E809982E0EEA22C5AF5CDDF05473F6ECBE353119591E6CDCB7127E";
		std::string HashOfABCDE = "107EEF69D795B14C8411EEBEFA897429682108397680377C78E5D214F014916F";
		std::string HashOfDefaultDataWithHMACWithShortKey = "D818A87A70949BDA7DE9765650D665C49B1B5CF11B05A1780901C46A91FFD786";
		std::string HashOfDefaultDataWithHMACWithLongKey = "989E63ED61D8A5D1F55A534C4835129924B28F6E41AE7924596A8874CF4082F6";

		//
		IHash HashInstance = HashFactory::Crypto::CreateBlake2SP(32, {});
		IHMACNotBuildIn HMACInstance = HashFactory::HMAC::CreateHMAC(HashInstance, {});
		IHash HashInstanceWithKey = HashFactory::Crypto::CreateBlake2SP(32, ZeroToThirtyOneBytes);

		HashLibStringArray KeyedTestVectors = Blake2SPTestVectors::KeyedBlake2SP;
		HashLibStringArray UnkeyedTestVectors = Blake2SPTestVectors::UnKeyedBlake2SP;
		
		SECTION("TestCheckKeyedTestVectors")
		{
			std::string ActualString, ExpectedString;
			Int32 i;

			for (i = 0; i < KeyedTestVectors.size(); i++)
			{
				ActualString = HashInstanceWithKey->ComputeBytes(GenerateByteArrayInRange(0, i))->ToString();
				ExpectedString = KeyedTestVectors[i];
				REQUIRE(ExpectedString == ActualString);
			}
		}

		SECTION("TestCheckUnKeyedTestVectors")
		{
			std::string ActualString, ExpectedString;
			Int32 i;

			for (i = 0; i < UnkeyedTestVectors.size(); i++)
			{
				ActualString = HashInstance->ComputeBytes(GenerateByteArrayInRange(0, i))->ToString();
				ExpectedString = UnkeyedTestVectors[i];
				REQUIRE(ExpectedString == ActualString);
			}
		}
		
		SECTION("HMACWithDefaultDataAndLongKey")
		{
			IHMACNotBuildIn hmac = HashFactory::HMAC::CreateHMAC(HashInstance);
			hmac->SetKey(HMACLongKeyBytes);

			std::string String = HashOfDefaultDataWithHMACWithLongKey;
			std::string ActualString = hmac->ComputeBytes(DefaultDataBytes)->ToString();

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