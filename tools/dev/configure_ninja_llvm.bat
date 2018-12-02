@ECHO off
setlocal

REM =========================================================================================
REM This script configures the project for Ninja with ideally any toolchain
REM Before calling this script, it is important to add Ninja executable to the PATH and
REM run a setting tool such as Microsoft's vcvarsall.bat to set up a working environment.
REM Be aware that, due to a CMake Ninja generator issue, mixing 64/32 bits is not possible:
REM https://gitlab.kitware.com/cmake/cmake/issues/16259
REM i.e. if clang is installed for 64bits, vcvarsall.bat should be called with 64 bit options
REM =========================================================================================

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

where clang-cl > nul 2>&1
if %errorlevel% NEQ 0 (
	echo Cannot locate CLang compiler cl, either it is not installed or it is not in the PATH.
	pause
	exit /B
)

where lld-link > clang_linker
if %errorlevel% NEQ 0 (
	del /Q /F clang_linker
	echo Cannot locate CLang linker lld-link, either it is not installed or it is not in the PATH.
	pause
	exit /B
)

set /p LINKER=<clang_linker
del /Q /F clang_linker
set CC=clang-cl
set CXX=clang-cl

set BUILD_NAME=build-Ninja-llvm

pushd "..\..\"
	if not exist %BUILD_NAME% ( mkdir %BUILD_NAME% )
	if exist %BUILD_OUTPUT_NAME% ( rmdir /S /Q %BUILD_OUTPUT_NAME% )

	pushd %BUILD_NAME%
		%CMAKE_BIN% .. -G Ninja -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_INSTALL_PREFIX=%BUILD_INSTALL_PATH% -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBOOST_ROOT=%BOOST_ROOT_DIR% ^
		-DCMAKE_LINKER="%LINKER%" ^
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
