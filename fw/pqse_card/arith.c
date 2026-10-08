/* arith.c - libgcc mul/div helpers for RV32I (div by 0 as in the M extension) */
#include <stdint.h>

unsigned __mulsi3(unsigned a, unsigned b);
unsigned __udivsi3(unsigned n, unsigned d);
unsigned __umodsi3(unsigned n, unsigned d);
int __divsi3(int a, int b);
int __modsi3(int a, int b);

unsigned __mulsi3(unsigned a, unsigned b)
{
    unsigned r = 0;
    while (b) {
        if (b & 1)
            r += a;
        a <<= 1;
        b >>= 1;
    }
    return r;
}

static unsigned udivmod(unsigned n, unsigned d, unsigned *rem)
{
    unsigned q = 0, r = 0;
    int i;
    if (d == 0) {
        *rem = n;
        return 0xFFFFFFFFu;
    }
    for (i = 31; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1);
        if (r >= d) {
            r -= d;
            q |= 1u << i;
        }
    }
    *rem = r;
    return q;
}

unsigned __udivsi3(unsigned n, unsigned d)
{
    unsigned r;
    return udivmod(n, d, &r);
}

unsigned __umodsi3(unsigned n, unsigned d)
{
    unsigned r;
    udivmod(n, d, &r);
    return r;
}

int __divsi3(int a, int b)
{
    unsigned ua = a < 0 ? 0u - (unsigned)a : (unsigned)a;
    unsigned ub = b < 0 ? 0u - (unsigned)b : (unsigned)b;
    unsigned r, q;
    if (b == 0)
        return -1;
    q = udivmod(ua, ub, &r);
    return (int)((a < 0) != (b < 0) ? 0u - q : q);
}

int __modsi3(int a, int b)
{
    unsigned ua = a < 0 ? 0u - (unsigned)a : (unsigned)a;
    unsigned ub = b < 0 ? 0u - (unsigned)b : (unsigned)b;
    unsigned r;
    udivmod(ua, ub, &r);                    /* b = 0: r = |a|, signed back below */
    return (int)(a < 0 ? 0u - r : r);
}
