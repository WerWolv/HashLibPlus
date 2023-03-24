#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace CryptoHashTests
{
	TEST_CASE("Haval_4_256Tests")
	{
		std::string HashOfEmptyData = "C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B";
		std::string HashOfDefaultData = "B5E97F406CBD4C36CC549072713E733EE31A5F9F23DD6C5982D3A239A9B38434";
		std::string HashOfOnetoNine = "DDC95DF473DD169456484BEB4B04EDCA83A5572D9D7ECCD00092365AE4EF8D79";
		std::string HashOfABCDE = "8F9B46785E52C6C48A0178EDC66D3C23C220D15E52C3C8A13E1CD45D21369193";
		std::string HashOfDefaultDataWithHMACWithShortKey = "FD0122B375A581D3F06DB6EB992F9A3F46657091E427BB8BD247D835CC086437";
		std::string HashOfDefaultDataWithHMACWithLongKey = "149D5BF6ED121FE862D15409C0F40913AEEBD563CCC3F2CD74E0979A09CAC2F1";
		
		IHash HashInstance = HashFactory::Crypto::CreateHaval_4_256();
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