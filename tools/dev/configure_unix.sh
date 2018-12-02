#!/bin/sh

# =========================================================================================
# This script configures the project to compile with Clang or gcc
# Works under linux as well as Unix-like OS such as OpenBSD
# =========================================================================================

BUILD_GENERATOR="Unix Makefiles"

BUILD_COMPILER_C=gcc
BUILD_COMPILER_CXX=g++
#BUILD_COMPILER_C=clang
#BUILD_COMPILER_CXX=clang++

BUILD_TYPE=Debug
#BUILD_TYPE=Release

BUILD_INSTALL_PATH="..\install"
HASHLIBCXX_SHARED_LIBS=OFF
HASHLIBCXX_BUILD_TESTS=OFF
HASHLIBCXX_BUILD_SAMPLES=OFF
HASHLIBCXX_STD_ASSERT=ON
HASHLIBCXX_STD_STRING=ON
HASHLIBCXX_USE_LOOPS_UNROLLING=OFF

# =========================================================================================
# =========================================================================================

COMPILER_BIN_C=$(eval command -v $BUILD_COMPILER_C)
COMPILER_BIN_CXX=$(eval command -v $BUILD_COMPILER_CXX)

if [ -z "$COMPILER_BIN_C" ] || [ -z "$COMPILER_BIN_CXX" ]; then 
	echo >&2 "Cannot locate $BUILD_COMPILER. Please install $BUILD_COMPILER and run again this batch.";
	exit 1; 
fi

command -v cmake >/dev/null 2>&1 || { 
	echo >&2 "Cannot locate CMake. Please install CMake and run again this batch.";
	exit 1; 
}

BUILD_NAME=build-$BUILD_COMPILER_C-$BUILD_TYPE

cd ..
cd ..

if [ ! -d "$BUILD_NAME" ]; then	mkdir "$BUILD_NAME"; fi
if [ -d "$BUILD_INSTALL_PATH" ]; then rm -rf "$BUILD_INSTALL_PATH"; fi

cd "$BUILD_NAME"
export CC=$COMPILER_BIN_C
export CXX=$COMPILER_BIN_CXX
cmake .. -G "$BUILD_GENERATOR" -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_INSTALL_PREFIX="$BUILD_INSTALL_PATH" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
-DBUILD_SHARED_LIBS=$HASHLIBCXX_SHARED_LIBS \
-DHASHLIBCXX_BUILD_TESTS=$HASHLIBCXX_BUILD_TESTS \
-DHASHLIBCXX_BUILD_SAMPLES=$HASHLIBCXX_BUILD_SAMPLES \
-DHASHLIBCXX_STD_ASSERT=$HASHLIBCXX_STD_ASSERT \
-DHASHLIBCXX_STD_STRING=$HASHLIBCXX_STD_STRING \
-DHASHLIBCXX_USE_LOOPS_UNROLLING=$HASHLIBCXX_USE_LOOPS_UNROLLING
