#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace CryptoHashTests
{
	TEST_CASE("SHA2_512_224Tests")
	{
		std::string HashOfEmptyData = "6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4";
		std::string HashOfDefaultData = "7A95749FB7F4489A45275556F5D905D28E1B637DCDD6537336AB6234";
		std::string HashOfDefaultDataWithHMACWithLongKey = "90D4733F36AAACD0227DBBB1706DB44BB8F6900748A9DBA7544218A8";
		std::string HashOfDefaultDataWithHMACWithShortKey = "9BC318A84B90F7FF55C53E3F4B602EAD13BB579EB1794455B29562B4";
		std::string HashOfOnetoNine = "F2A68A474BCBEA375E9FC62EAAB7B81FEFBDA64BB1C72D72E7C27314";
		std::string HashOfABCDE = "880E79BB0A1D2C9B7528D851EDB6B8342C58C831DE98123B432A4515";

		IHash HashInstance = HashFactory::Crypto::CreateSHA2_512_224();
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