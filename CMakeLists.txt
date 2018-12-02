cmake_minimum_required (VERSION 3.10 FATAL_ERROR)

project(hashkitcxx LANGUAGES CXX VERSION 1.0.0)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(WarningLevel)
include(WarningAsError)

option(BUILD_SHARED_LIBS "Build a shared library instead than a static library" OFF)
option(HASHLIBCXX_BUILD_TESTS "Build all the unit tests" OFF)
option(HASHLIBCXX_BUILD_SAMPLES "Build all the example apps" OFF)
option(HASHLIBCXX_STD_ASSERT "Enable use of assert() from <cassert> header file. When OFF, asserts are disabled" ON)
option(HASHLIBCXX_STD_STRING "Enable use of std::string from <string> header file.  When OFF strings won't be used, so the library interface uses only POD types" ON)
option(HASHLIBCXX_USE_LOOPS_UNROLLING "Use loop unrolling technique in any hashing algorithm that supports it" OFF)

# Erase any warning level set by default for MSVC compilers
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]|/Wall")
        string(REGEX REPLACE "/W[0-4]|/Wall" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    endif()
endif()

add_library(${PROJECT_NAME}
	${PROJECT_NAME}/hash_utils.hpp
	${PROJECT_NAME}/hash_sha2.hpp
	${PROJECT_NAME}/hash_sha2.cpp)
	
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
)

# Checking compiler features
target_compile_features(${PROJECT_NAME} 
    PRIVATE cxx_noexcept
    PRIVATE cxx_nullptr
    PRIVATE cxx_override
    PRIVATE cxx_final
    PRIVATE cxx_nonstatic_member_init
    PRIVATE cxx_rvalue_references)
	
# Compile options from the user
if (HASHLIBCXX_STD_ASSERT)
	target_compile_definitions(${PROJECT_NAME} PUBLIC "HASHLIBCXX_STD_ASSERT")
endif()

if (HASHLIBCXX_STD_STRING)
	target_compile_definitions(${PROJECT_NAME} PUBLIC "HASHLIBCXX_STD_STRING")
endif()

if (HASHLIBCXX_USE_LOOPS_UNROLLING)
	target_compile_definitions(${PROJECT_NAME} PUBLIC "HASHLIBCXX_USE_LOOPS_UNROLLING")
endif()

# Compile options (warnings)
set_warning_level()
set_warning_as_error()

# Install
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION lib
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

install(DIRECTORY hashkitcxx
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include
	FILES_MATCHING PATTERN "*.hpp")

# Install pdb files (if any) when using MSVC compiler
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	get_property(type TARGET ${PROJECT_NAME} PROPERTY TYPE)
	if ("${type}" STREQUAL "SHARED_LIBRARY")
        install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}>
            DESTINATION lib
			COMPONENT development
            OPTIONAL)
	endif()
endif()

# Tests
if (HASHLIBCXX_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# Samples
if (HASHLIBCXX_BUILD_SAMPLES)
    add_subdirectory(samples)
endif()
