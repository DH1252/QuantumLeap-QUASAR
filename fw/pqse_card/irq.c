/* irq.c - trap handler (RV_IRQ=1): interrupts to irq_handler, exceptions halt */
#include <stdint.h>
#include "pqse_hw.h"

void irq_handler(uint32_t pending);
uint32_t trap(uint32_t mcause, uint32_t mepc);

/* default: disable unhandled sources so they do not interrupt again */
__attribute__((weak)) void irq_handler(uint32_t pending)
{
    IRQ = ((IRQ >> 4) & 0xFu) & ~pending;
}

static void hex8(uint32_t v)
{
    int i;
    for (i = 28; i >= 0; i -= 4)
        CONSOLE = (uint8_t)"0123456789abcdef"[(v >> i) & 15];
}

uint32_t trap(uint32_t mcause, uint32_t mepc)
{
    const char *s;
    if (mcause & 0x80000000u) {
        uint32_t r = IRQ;
        irq_handler(r & (r >> 4) & 0xFu);
        return mepc;
    }
    for (s = "\ntrap: mcause "; *s; s++)
        CONSOLE = (uint8_t)*s;
    hex8(mcause);
    for (s = " mepc "; *s; s++)
        CONSOLE = (uint8_t)*s;
    hex8(mepc);
    CONSOLE = '\n';
    for (;;)
        ;
}
