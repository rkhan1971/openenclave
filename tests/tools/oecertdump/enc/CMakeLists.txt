# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oecertdump_t.h oecertdump_t.c oecertdump_args.h
  DEPENDS ../oecertdump.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecertdump.edl
          --search-path ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_enclave(
  TARGET
  oecertdump_enc
  CRYPTO_LIB
  mbedtls
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/oecertdump_t.c)

# Need for the generated file oecertdump_t.h
enclave_include_directories(oecertdump_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
