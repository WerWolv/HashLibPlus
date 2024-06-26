cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(HashLibPlus VERSION 1.0)

file(GLOB_RECURSE SRC_FILES Base/*.cpp Crypto/*.cpp Params/*.cpp Utils/*.cpp)
add_executable(HashLibPlus EXCLUDE_FROM_ALL HashLibPlus.cpp ${SRC_FILES})
target_include_directories(HashLibPlus 
	PUBLIC 
		${CMAKE_CURRENT_SOURCE_DIR}/Base
		${CMAKE_CURRENT_SOURCE_DIR}/Checksum
		${CMAKE_CURRENT_SOURCE_DIR}/Crypto
		${CMAKE_CURRENT_SOURCE_DIR}/Enum
		${CMAKE_CURRENT_SOURCE_DIR}/Hash32
		${CMAKE_CURRENT_SOURCE_DIR}/Hash64
		${CMAKE_CURRENT_SOURCE_DIR}/Hash128
		${CMAKE_CURRENT_SOURCE_DIR}/Interfaces
		${CMAKE_CURRENT_SOURCE_DIR}/KDF
		${CMAKE_CURRENT_SOURCE_DIR}/MAC
		${CMAKE_CURRENT_SOURCE_DIR}/Nullable
		${CMAKE_CURRENT_SOURCE_DIR}/NullDigest
		${CMAKE_CURRENT_SOURCE_DIR}/Params
		${CMAKE_CURRENT_SOURCE_DIR}/Utils
)

add_library(hashplus STATIC ${SRC_FILES})
target_include_directories(hashplus 
	PUBLIC 
		${CMAKE_CURRENT_SOURCE_DIR}/Base
		${CMAKE_CURRENT_SOURCE_DIR}/Checksum
		${CMAKE_CURRENT_SOURCE_DIR}/Crypto
		${CMAKE_CURRENT_SOURCE_DIR}/Enum
		${CMAKE_CURRENT_SOURCE_DIR}/Hash32
		${CMAKE_CURRENT_SOURCE_DIR}/Hash64
		${CMAKE_CURRENT_SOURCE_DIR}/Hash128
		${CMAKE_CURRENT_SOURCE_DIR}/Interfaces
		${CMAKE_CURRENT_SOURCE_DIR}/KDF
		${CMAKE_CURRENT_SOURCE_DIR}/MAC
		${CMAKE_CURRENT_SOURCE_DIR}/Nullable
		${CMAKE_CURRENT_SOURCE_DIR}/NullDigest
		${CMAKE_CURRENT_SOURCE_DIR}/Params
		${CMAKE_CURRENT_SOURCE_DIR}/Utils
)

if (HASHLIBPLUS_ENABLE_TESTS)
	add_executable(HashLibPlus_Tests EXCLUDE_FROM_ALL HashLibPlus.Tests/HashLibPlus.Tests.cpp)
	target_include_directories(HashLibPlus_Tests
		PUBLIC
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/Base
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/Checksum
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/Crypto
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/Hash32
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/Hash64
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/Hash128
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/KDF
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/MAC
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/XOF
			${CMAKE_CURRENT_SOURCE_DIR}/HashLibPlus.Tests/NullDigest
	)
	add_subdirectory(HashLibPlus.Tests/Catch2-2.13.6 )
	target_link_libraries(HashLibPlus_Tests PUBLIC hashplus)
endif()