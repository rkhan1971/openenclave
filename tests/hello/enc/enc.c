// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include "hello_t.h"

int hello_ecall(const char* msg)
{
    int retval;

    printf("enclave: %s\n", msg);

    if (hello_ocall(&retval, msg) != OE_OK)
        fprintf(stderr, "hello_ocall() failed\n");

    return retval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
