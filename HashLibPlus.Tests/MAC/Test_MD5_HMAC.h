#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace MACTests
{
	TEST_CASE("MD5_HMACTests")
	{
		std::string ExpectedString, ActualString;

		std::string HashOfEmptyData = "74E6F7298A9C2D168935F58C001BAD88";
		std::string HashOfDefaultData = "E26A378B9A20DE63EE8C29402396553D";
		std::string HashOfOnetoNine = "56BEDC1F02772E32FDC71214BB795047";
		std::string HashOfABCDE = "B6DE7A4249C9E8338098CB8B18E14CA5";
	
		IHash HashInstance = HashFactory::HMAC::CreateHMAC(HashFactory::Crypto::CreateMD5(), EmptyBytes);
		IMACNotBuildIn MacInstance = HashFactory::HMAC::CreateHMAC(HashFactory::Crypto::CreateMD5(), EmptyBytes);;
		IMACNotBuildIn MacInstanceTwo = HashFactory::HMAC::CreateHMAC(HashFactory::Crypto::CreateMD5(), OneToNineBytes);;

		SECTION("ChangeKeyAndInitializeWorks")
		{
			ExpectedString = MacInstanceTwo->ComputeBytes(DefaultDataBytes)->ToString();
			MacInstance->SetKey(OneToNineBytes);
			MacInstance->Initialize();
			MacInstance->TransformBytes(DefaultDataBytes);
			ActualString = MacInstance->TransformFinal()->ToString();

			REQUIRE(ExpectedString == ActualString);
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
		
		SECTION("TestSettingNullHashInstanceThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::HMAC::CreateHMAC(nullptr, EmptyBytes),
				ArgumentNullHashLibException);
		}

		SECTION("TestMACCloneIsCorrect")
		{
			IMACNotBuildIn Original = MacInstance;
			IMACNotBuildIn Copy;

			Original->SetKey(HMACLongKeyBytes);
			Original->Initialize();
			Original->TransformBytes(ChunkOne);

			// Make Copy Of Current State
			Copy = Original->CloneMAC();

			Original->TransformBytes(ChunkTwo);
			std::string String = Original->TransformFinal()->ToString();

			Copy->TransformBytes(ChunkTwo);
			std::string ActualString = Copy->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

	}
}
