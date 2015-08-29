#include <assert.h>
#include <stdio.h>

typedef unsigned char u8;
typedef unsigned long long u64;

void randombytes(u8 *buf, u64 nbytes) {
    FILE *fp = 0; 

    assert(buf && nbytes);
    assert(fp = fopen("/dev/urandom", "r"));
    assert((fread(buf, nbytes, 1, fp)) == 1);
    assert(!fclose(fp));
}
