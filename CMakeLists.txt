#packet vm makefile

cmake_minimum_required(VERSION 3.12.1)
project(ebpf_vm)

set(VERSION "1.0.1")
set(RELEASE "1")

set(BIN_INSTALL_PREFIX "/usr/bin/")
set(INCLUDE_INSTALL_PREFIX "/usr/include/ctinspector")
set(LIB_INSTALL_PREFIX "/usr/lib64/")



set(CPACK_PACKAGE_NAME "ctinspector")
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_PACKAGE_RELEASE ${RELEASE})
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION})
set(CPACK_SOURCE_IGNORE_FILES "/build/;${CPACK_SOURCE_IGNORE_FILES}")
set(CPACK_SOURCE_IGNORE_FILES "/*.git/;${CPACK_SOURCE_IGNORE_FILES}")
set(CPACK_SOURCE_IGNORE_FILES "/*.md/;${CPACK_SOURCE_IGNORE_FILES}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/CTinspector.spec.in" "${CMAKE_CURRENT_BINARY_DIR}/CTinspector.spec" @ONLY IMMEDIATE)
include(CPack)



add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

add_compile_options(-g)
add_subdirectory (ebpf_vm_executor)
add_subdirectory (ebpf_vm_test)
