function(set_warning_level)

    # Warning level
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        if (MSVC_VERSION LESS 1910)
            target_compile_options(${PROJECT_NAME} PRIVATE "/W4")
        else()
            target_compile_options(${PROJECT_NAME} PRIVATE "/Wall")
            message(AUTHOR_WARNING "Using /Wall under Visual Studio 2017 requires /experimental:external")
            target_compile_options(${PROJECT_NAME} 
                PRIVATE "/experimental:external"
                PRIVATE "/external:env:INCLUDE"
                PRIVATE "/external:W3")
            target_compile_options(${PROJECT_NAME} 
                PRIVATE "/wd4514"  #warning: unreferenced inline function has been removed
                PRIVATE "/wd4820"  #warning: 'bytes' bytes padding added after data member
                PRIVATE "/wd4193"  #warning: pragma warning(pop): no matching '#pragma warning(push)'
                PRIVATE "/wd5045"  #warning: compiler will insert Spectre mitigation for memory load if /Qspectre switch specified
                PRIVATE "/wd4710"  #warning: 'fn' function not inlined
                PRIVATE "/wd4711") #warning function 'fn' selected for automatic inline expansion
        endif()
    elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        target_compile_options(${PROJECT_NAME} 
            PRIVATE "-Wall"
            PRIVATE "-Wextra"
            PRIVATE "-pedantic")
    #elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
    elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
        target_compile_options(${PROJECT_NAME} 
            PRIVATE "-Wall"
            PRIVATE "-Weverything"
            PRIVATE "-Wno-c++98-compat-pedantic")
        if (MSVC)
            target_compile_options(${PROJECT_NAME} PRIVATE "-Wno-unused-command-line-argument")
        endif()
    else()
        message(WARNING "Compiler ${CMAKE_CXX_COMPILER_ID} not found in CMake configuration. Default warning level and options will be used.")
    endif()

endfunction(set_warning_level)
