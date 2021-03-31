
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct sstic_get_key
{
    unsigned long id;
    char key[16];
};

union sstic_arg
{
    struct sstic_get_key get_key;
};

#define GET_KEY 0xC0185304

int sstic_getkey(unsigned char key[16], uint64_t id)
{
    int ret;
    union sstic_arg arg;
    arg.get_key.id = id;
    int session = open("/dev/sstic", O_RDWR);
    if(session == -1)
    {
        perror("open session");
        abort();
    }
    ret = ioctl(session, GET_KEY, &arg);
    if(ret == -1)
    {
        perror("get_key");
        close(session);
        return -1;
    }
    memcpy(key, arg.get_key.key,16);
    close(session);
    return 0;
}

int main() {
    unsigned char key[16];
    uint64_t ident = 0x0011223344deed;

    if (sstic_getkey(key, ident) == 0) {
        printf("key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            key[0], key[1], key[2], key[3],
            key[4], key[5], key[6], key[7],
            key[8], key[9], key[10], key[11],
            key[12], key[13], key[14], key[15]);
    } else {
        printf("error\n");
    }

    return 0;
}
