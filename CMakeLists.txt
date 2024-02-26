set(VCPKG_INC "/git/vcpkg/installed/x64-windows/include")
set(VCPKG_LIB "/git/vcpkg/installed/x64-windows/lib")

#
# -------------------- Do not edit below this line --------------------
#

cmake_minimum_required(VERSION 3.9)
set(PROJECT_NAME "lora-ws")
project(${PROJECT_NAME} VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)

find_library(LIBMICROHTTPD NAMES microhttpd libmicrohttpd-dll.lib HINTS /usr/lib/x86_64-linux-gnu/ ${VCPKG_LIB})

set(ARGTABLE "third-party/argtable3/argtable3.c")
set(LORAWAN_SRC
	lorawan/lorawan-conv.cpp
	lorawan/lorawan-error.cpp
	lorawan/lorawan-msg.cpp
	lorawan/lorawan-string.cpp
	lorawan/lorawan-date.cpp
	lorawan/lorawan-mac.cpp
	lorawan/lorawan-packet-storage.cpp
	lorawan/lorawan-types.cpp
	lorawan/key/key128gen.cpp
	lorawan/proto/gw/proto-gw-parser.cpp
	lorawan/proto/gw/basic-udp.cpp
	third-party/system/crypto/aes.c third-party/system/crypto/cmac.c
)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	# avoid Error LNK2038 mismatch detected for 'RuntimeLibrary': value 'MT_StaticRelease' doesn't match value 'MD_DynamicRelease'
	# set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
	# set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
	set(OS_SPECIFIC_LIBS wsock32 ws2_32 Userenv)
endif()

add_executable(lora-ws
	svc.cpp
	lora-ws.cpp
	query-parser-json.cpp
	${LORAWAN_SRC}
	${ARGTABLE}
	third-party/daemonize.cpp
	third-party/base64/base64.cpp
)
target_link_libraries(lora-ws PRIVATE ${OS_SPECIFIC_LIBS} ${LIBMICROHTTPD})
target_include_directories(lora-ws PRIVATE "." "third-party" ${VCPKG_INC})
