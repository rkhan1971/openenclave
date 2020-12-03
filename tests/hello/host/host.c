// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <assert.h>
#include "hello_u.h"

int hello_ocall(const char* msg)
{
    printf("host: %s\n", msg);
    return 12345;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = oe_create_hello_enclave(argv[1], type, flags, NULL, 0, &enclave);
    assert(result == OE_OK);

    int retval;
    result = hello_ecall(enclave, &retval, "Hello!");
    assert(result == OE_OK);
    assert(retval == 12345);

    result = oe_terminate_enclave(enclave);
    assert(result == OE_OK);

    return 0;
}
