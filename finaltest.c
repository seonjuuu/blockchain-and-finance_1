#include <stdio.h>
#include <string.h>
#include <inttypes.h>



#define ROTL_ULONG(x, n) ((uint32_t)((x) << (n)) | (uint32_t)((x) >> (32 - (n))))
#define ROTR_ULONG(x, n) ((uint32_t)((x) >> (n)) | (uint32_t)((x) << (32 - (n))))
//1-1


// 1-2
uint32_t calc_hw(uint8_t *in, uint32_t inlen)
{
    uint32_t hw =0;
    hw = 1;

    uint32_t i = 1;
    i = i << (inlen-2);
    while(i != 0){
        uint32_t chk = (in&i);
        if(chk)
        {
            hw++;
        }
        i = i>>1;
    }

    return hw;
}

// 1-3
void toy_hash(uint8_t *in, uint8_t inlen)
{
    uint32_t c[inlen] = {0,};
    for(int i=1; i<inlen+1; i++)
    {
        uint32_t c

    }


}

void toy_mac(uint8_t *tag, uint8_t *key, uint8_t *in, uint8_t inlen)
{


    
}



void main()
{
    //1-1
    uint32_t a = 0x11223344;
    uint32_t b , c, d, e,f,g;

    b = ROTL_ULONG(a,16);
    c = ROTR_ULONG(a,16);
    d = (b&0xff000000);
    d = ROTR_ULONG(d,8);
    e = (b&0x00ff0000);
    e = ROTL_ULONG(e,8);

    f = (c&0x0000ff00);
    f = ROTR_ULONG(f,8);
    g = (c&0x000000ff);
    g = ROTL_ULONG(g,8);

    a = d^e^f^g;

    printf("%x",a);





    
}