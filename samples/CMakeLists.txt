project(samples LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_custom_target(${PROJECT_NAME})

set(SAMPLES
	file2sha
	input_hash
)

foreach(SAMPLE ${SAMPLES})
	add_executable(${SAMPLE} EXCLUDE_FROM_ALL ${SAMPLE}.cpp)
	add_dependencies(${PROJECT_NAME} ${SAMPLE})
	set_target_properties(${SAMPLE} PROPERTIES FOLDER samples)
	
	# HashKitCXX library
	add_dependencies(${SAMPLE} hashkitcxx)
	target_link_libraries(${SAMPLE} hashkitcxx)
	target_include_directories(${SAMPLE} SYSTEM PUBLIC ${PROJECT_SOURCE_DIR}/..)
endforeach()
