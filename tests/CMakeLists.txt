project(tests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()
add_executable(${PROJECT_NAME} EXCLUDE_FROM_ALL
	test.cpp
	common.hpp
	sha2.hpp)

# Boost
find_package(Boost 1.67.0 REQUIRED COMPONENTS system filesystem unit_test_framework)
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC ${Boost_INCLUDE_DIRS})

# HashKitCXX library
add_dependencies(${PROJECT_NAME} hashkitcxx)
target_link_libraries(${PROJECT_NAME} hashkitcxx)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/..)

add_test(AllTests ${PROJECT_NAME})
