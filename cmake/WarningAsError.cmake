function(set_warning_as_error)

    # Warning as error
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        target_compile_options(${PROJECT_NAME} PRIVATE "/WX")
    elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
        target_compile_options(${PROJECT_NAME} PRIVATE "-Werror")
    #elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
    else()
        message(WARNING "Compiler ${CMAKE_CXX_COMPILER_ID} not found in CMake configuration. Warning-as-error will use the default behaviour set from the compiler.")
    endif()

endfunction(set_warning_as_error)
