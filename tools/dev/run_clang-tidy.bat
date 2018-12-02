@ECHO off
setlocal

where clang > clang_compiler
if %errorlevel% NEQ 0 (
	del /Q /F clang_compiler
	echo Cannot locate CLang linker lld-link, either it is not installed or it is not in the PATH.
	pause
	exit /B
)

set /p LLVM_ROOT_DIR=<clang_compiler
del /Q /F clang_compiler

python llvm_path.py "%LLVM_ROOT_DIR%" > llvm_path
set /p LLVM_ROOT_DIR=<llvm_path
del /Q /F llvm_path

pushd "..\..\"
	if not exist "build-Ninja-llvm" (
		echo Cannot find Ninja-llvm build. Run configure_ninja_llvm first.
		pause
		exit /B
	)
	
	python "%LLVM_ROOT_DIR%\share\clang\run-clang-tidy.py" -p="build-Ninja-llvm" -fix
popd
