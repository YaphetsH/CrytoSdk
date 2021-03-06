

cmake_minimum_required(VERSION 3.4.1)
message(STATUS "******************************************************************")
message(STATUS "CMAKE_SOURCE_DIR->" ${CMAKE_SOURCE_DIR})
message(STATUS "PROJECT_SOURCE_DIR->)" ${PROJECT_SOURCE_DIR})
message(STATUS "******************************************************************")
include_directories("${CMAKE_SOURCE_DIR}/include")
# 添加两个openssl预编译库
add_library(openssl-crypto
        STATIC
        IMPORTED)

set_target_properties(openssl-crypto
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/jniLibs/${ANDROID_ABI}/libcrypto.a)

add_library(openssl-ssl
        STATIC
        IMPORTED)

set_target_properties(openssl-ssl
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/jniLibs/${ANDROID_ABI}/libssl.a)
# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             QHCipher

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             qhcipher.c  )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       QHCipher

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} openssl-ssl openssl-crypto)