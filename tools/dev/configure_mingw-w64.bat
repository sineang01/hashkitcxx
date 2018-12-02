@ECHO off
setlocal

REM =========================================================================================
REM This script configures the project using MinGW-w64 running natively on Microsoft Windows platform.
REM The project will be compiled in 32 or 64 bits accordingly to the MinGW-w64 environment.
REM =========================================================================================

set BUILD_GENERATOR=MinGW Makefiles
set BUILD_GENERATOR_SHORT=MinGW-w64

set BUILD_TYPE=Debug
REM set BUILD_TYPE=Release

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

:CMAKE_LOOKUP
set CMAKE_BIN=cmake.exe
where "%CMAKE_BIN%" > nul 2>&1
if %errorlevel% NEQ 0 (
	if exist "C:\Program Files\CMake\bin\%CMAKE_BIN%" (
		set CMAKE_BIN="C:\Program Files\CMake\bin\%CMAKE_BIN%"
		goto :MINGW_GCC_LOOKUP
	)
	
	if exist "C:\Program Files (x86)\CMake\bin\%CMAKE_BIN%" (
		set CMAKE_BIN="C:\Program Files (x86)\CMake\bin\%CMAKE_BIN%"
		goto :MINGW_GCC_LOOKUP
	)
	
	echo Cannot locate CMake, either it is not installed or it is not in the default locations.
	echo Please install CMake and run again this batch
	pause
	exit /B
)

:MINGW_GCC_LOOKUP
where "i686-w64-mingw32-g++.exe" > nul 2>&1
if %errorlevel% EQU 0 (
	set BUILD_PLATFORM=x86
	goto :CONFIGURE
)

where "x86_64-w64-mingw32-g++.exe" > nul 2>&1
if %errorlevel% EQU 0 (
	set BUILD_PLATFORM=x64
	goto :CONFIGURE
)

echo Cannot locate compatible MinGW-w64 g++ binaries
echo Please make sure you are running this script from within a MinGW-w64 compatible environment
pause
exit /B

:CONFIGURE
set BUILD_NAME=build-%BUILD_GENERATOR_SHORT%-%BUILD_TYPE%-%BUILD_PLATFORM%

pushd "..\..\"
	if not exist %BUILD_NAME% ( mkdir %BUILD_NAME% )
	if exist %BUILD_OUTPUT_NAME% ( rmdir /S /Q %BUILD_OUTPUT_NAME% )

	pushd "%BUILD_NAME%"
		%CMAKE_BIN% .. -G "%BUILD_GENERATOR%" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_INSTALL_PREFIX=%BUILD_INSTALL_PATH% -DBOOST_ROOT=%BOOST_ROOT_DIR% ^
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
