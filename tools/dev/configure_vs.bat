@ECHO off
setlocal

REM =========================================================================================
REM This script configures the project for the Visual Studio IDE and MSVC compilers or LLVM
REM It works with multiple versions of Visual Studio and allows using multiple toolchains
REM =========================================================================================

set BUILD_GENERATOR=Visual Studio 15 2017
set BUILD_GENERATOR_SHORT=Vs2017
REM set BUILD_GENERATOR=Visual Studio 14 2015
REM set BUILD_GENERATOR_SHORT=Vs2015

set BUILD_TOOLCHAIN=v141
REM set BUILD_TOOLCHAIN=v140
REM set BUILD_TOOLCHAIN=LLVM

set BUILD_PLATFORM=x86
REM set BUILD_PLATFORM=x64
REM set BUILD_PLATFORM=ARM

set BUILD_INSTALL_PATH="..\install"
set HASHLIBCXX_SHARED_LIBS=OFF
set HASHLIBCXX_BUILD_TESTS=OFF
set HASHLIBCXX_BUILD_SAMPLES=OFF
set HASHLIBCXX_STD_ASSERT=ON
set HASHLIBCXX_STD_STRING=ON
set HASHLIBCXX_USE_LOOPS_UNROLLING=OFF

set BOOST_ROOT_DIR=E:\boost\1_68_0

REM =========================================================================================
REM =========================================================================================

set CMAKE_BIN=cmake.exe
where "%CMAKE_BIN%" > nul 2>&1
if %errorlevel% NEQ 0 (
	if exist "C:\Program Files\CMake\bin\%CMAKE_BIN%" (
		set CMAKE_BIN="C:\Program Files\CMake\bin\%CMAKE_BIN%"
		goto :CONFIGURE
	)
	
	if exist "C:\Program Files (x86)\CMake\bin\%CMAKE_BIN%" (
		set CMAKE_BIN="C:\Program Files (x86)\CMake\bin\%CMAKE_BIN%"
		goto :CONFIGURE
	)
	
	echo Cannot locate CMake, either it is not installed or it is not in the default locations.
	echo Please install CMake and run again this batch
	pause
	exit /B
)

:CONFIGURE
set BUILD_NAME=build-%BUILD_GENERATOR_SHORT%-%BUILD_TOOLCHAIN%-%BUILD_PLATFORM%

pushd "..\..\"
	if not exist %BUILD_NAME% ( mkdir %BUILD_NAME% )
	if exist %BUILD_OUTPUT_NAME% ( rmdir /S /Q %BUILD_OUTPUT_NAME% )

	pushd %BUILD_NAME%
		if %BUILD_PLATFORM%==x86 ( set BUILD_GENERATOR_FULL="%BUILD_GENERATOR%" )
		if %BUILD_PLATFORM%==x64 ( set BUILD_GENERATOR_FULL="%BUILD_GENERATOR% Win64" )
		if %BUILD_PLATFORM%==ARM ( set BUILD_GENERATOR_FULL="%BUILD_GENERATOR% ARM" )

		%CMAKE_BIN% .. -G %BUILD_GENERATOR_FULL% -T "%BUILD_TOOLCHAIN%" -DCMAKE_INSTALL_PREFIX=%BUILD_INSTALL_PATH% -DBOOST_ROOT=%BOOST_ROOT_DIR% ^
		-DBUILD_SHARED_LIBS=%HASHLIBCXX_SHARED_LIBS% ^
		-DHASHLIBCXX_BUILD_TESTS=%HASHLIBCXX_BUILD_TESTS% ^
		-DHASHLIBCXX_BUILD_SAMPLES=%HASHLIBCXX_BUILD_SAMPLES% ^
		-DHASHLIBCXX_STD_ASSERT=%HASHLIBCXX_STD_ASSERT% ^
		-DHASHLIBCXX_STD_STRING=%HASHLIBCXX_STD_STRING% ^
		-DHASHLIBCXX_USE_LOOPS_UNROLLING=%HASHLIBCXX_USE_LOOPS_UNROLLING%
		
		if %errorlevel% NEQ 0 (
			echo Failed to configure project
			pause
			exit /B
		)
	popd
popd

pause
