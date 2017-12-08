cmake_minimum_required(VERSION 3.7)
project(pykerberos)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE ON)
include_directories(/usr/include/python2.6 SYSTEM)
#include_directories(/usr/include/python3.5m SYSTEM)
set(SOURCE_FILES
        src/base64.c
        src/base64.h
        src/kerberos.c
        src/kerberosbasic.c
        src/kerberosbasic.h
        src/kerberosgss.c
        src/kerberosgss.h
        src/kerberospw.c
        src/kerberospw.h)


add_library(kerberos SHARED ${SOURCE_FILES})
set_target_properties(kerberos PROPERTIES PREFIX "")
target_link_libraries(kerberos gssapi_krb5 krb5 k5crypto com_err)
unset(GSSAPI_EXT)