# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

add_enclave_test(tests/hello hello_host hello_enc)
