# HashKitCXX

[![License](https://img.shields.io/badge/License-BSD-blue.svg)](https://github.com/Snaipe/Criterion/blob/master/LICENSE)

## What is HashKitCXX
HashKitCXX is a modern, C++-native, hash library written in C++11.

## Why do we need yet another hash framework?
HashKitCXX is not a framework but a library of hashes, a collection, a development kit, and you don’t need to get the whole library to be able to use a specific hash type. You don’t even need to build a static or dynamic library to use these hashes, you can just download the source files you need and use them in your projects.

I've always struggled to find a hash library written in modern C++ code from which I can extract a specific hash algorithm to use it in my projects so I decided to start building my own.

This library doesn’t try to be as good or complete as, for example, [OpenSSL](https://github.com/openssl/openssl) or [Crypto C++](https://github.com/weidai11/cryptopp), but those are cryptographic framework and it is nearly impossible to extract one single hash algorithm from those projects, due to the dependencies with other source files in the same framework.

On the other hand, all you need to use a hash from HashKitCXX, is find the pair of source and header files that contains such algorithm and copy/paste them in your project. No other files will be necessary.

However, HashKitCXX can be build using as a static or dynamic library and installed in your system for ease of use, this will give you access to all hashes and all utilities, though you could obtain the same result simply downloading the content of the hashkitcxx/ directory.

## Major Features
  * Quick and easy to use. Just download the source and header files containing the hash you need and include the header in your project.
  * No external dependencies. As long as you can compile C++11 and have a C++ standard library available.
  * All the hash algorithms have no dependencies with other algorithms and are detachable from the rest of the library.
  * No name clashes. HashKitCXX is contained inside its own namespace and no macro or define are used in any header.
  * Warnings free. The library is compiled against multiple compilers and environments with all warning checks activated (see the full list below). It is also running checks using Clang pipeline, specifically clang-tidy and the Clang static analyzer.

## Downloads
Binary releases (if you need that) and source code archives are available on the [release page](https://github.com/sineang01/hashlibcxx/releases)

If you have a different platform and you can’t find already-made binaries for that platform, you can still download the source code and use it directly in your projects, or build from source.

## Compile
To download the latest available release, clone the master branch from the repository over GitHub.

    git clone https://github.com/sineang01/hashkitcxx.git
	
Now, compile the sources:

    cd hashkitcxx
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make
    sudo make install
	
If you want the samples built, then change the cmake above to:

    cmake -DCMAKE_BUILD_TYPE=Release -DHASHLIBCXX_BUILD_SAMPLES=ON ..
	
After running the above, you can then run `make samples`.

Optionally, you can also build and run the tests:

    cmake -DCMAKE_BUILD_TYPE=Release -DHASHLIBCXX_BUILD_TESTS=ON ..
    make tests
	
And that's it, now you can start playing with your newly installed hash library for C++.

## CMake defines

All the CMake defines are specified here:

| Option                         | Default | Description |
|--------------------------------|---------|-------------|
| HASHLIBCXX_BUILD_SAMPLES       | OFF     | Build all the example apps |
| HASHLIBCXX_BUILD_TESTS         | OFF     | Build all the unit tests |
| HASHLIBCXX_USE_LOOPS_UNROLLING | OFF     | Use loop unrolling technique in any hashing algorithm that supports it |
| HASHLIBCXX_STD_STRING          | ON      | Enable use of `std::string` from `<string>` header file. When OFF strings won't be used, so the library interface uses only POD types |
| HASHLIBCXX_STD_ASSERT          | ON      | Enable use of `assert()` from `<cassert>` header file. When OFF, asserts are disabled |

If you want to build HashLibCXX as a shared library instead than a static library use the option `BUILD_SHARED_LIBS`:

    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON ..
