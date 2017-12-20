cmake_minimum_required(VERSION 3.9)
project(tcpscan)

include_directories(src)
set(SOURCE_FILES
        src/tcpscan.c)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

# add extra include directories
include_directories(/usr/include)

# specify the executable (no libraries here)
add_executable(tcpscan src/tcpscan.c src/tcpscan.h src/tcplib.c src/tcplib.h)