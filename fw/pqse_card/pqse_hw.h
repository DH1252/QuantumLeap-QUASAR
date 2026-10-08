/* pqse_hw.h - register map of gowin/pqse_rv.v */
#ifndef PQSE_HW_H
#define PQSE_HW_H

#include <stdint.h>

/* clock from CLK_KHZ, 27 MHz if it reads 0 */
#define CLK_KHZ_DEFAULT 27000u
extern uint32_t clocks_ms;                  /* clocks per millisecond (main.c) */
#define CLOCKS_MS clocks_ms

/* SE bus: word a at 0x40000000 + 4a, 32-bit only */
#define SE(a)       (*(volatile uint32_t *)(0x40000000u + ((uint32_t)(a) << 2)))
#define SE_WORDS    0x1000u                 /* word addresses 0x000 - 0xFFF */
#define SE_ID       0x400u                  /* "PQSE" = 0x50515345 */
#define SE_VERSION  0x401u
#define SE_CTRL     0x402u                  /* [7:0] command, [8] injected seeds (TEST) */
#define SE_STATUS   0x403u                  /* [0] busy [1] done (write 1: clear) [15:8] result */
#define SE_CYCLES   0x404u                  /* clocks of the last command */

/* Peripherals */
#define IO(o)       (*(volatile uint32_t *)(0x80000000u + (o)))
#define UART_DATA   IO(0x00)  /* write: send byte (stalls while busy); read: [8] valid, [7:0] byte */
#define UART_STATUS IO(0x04)  /* [0] byte waiting [1] transmitter busy [2] overrun (write 1: clear) */
#define TIME        IO(0x08)  /* clock counter, 25 bits */
#define UART_DIV    IO(0x0C)  /* write: clocks per bit - 1 (115200 baud after reset) */
#define LEDS        IO(0x10)  /* [0] LED 4 [1] LED 5 */
#define CONSOLE     IO(0x14)  /* byte for the PC (USB board register 0x7F1) */
#define CONSOLE_IN  IO(0x18)  /* read: [8] valid, [7:0] byte from the PC (board register 0x7F2) */
#define CLK_KHZ     IO(0x34)  /* read: clock in kHz (0 if absent) */
#define CPU_W       IO(0x38)  /* read: SERV width, 1 or 4 (0 if absent: 1); 32 for Gracilis */
#define TIME_MASK   0x1FFFFFFu

/* event sources for WAIT and interrupts (RV_IRQ=1) */
#define IRQ         IO(0x1C)  /* read: [3:0] pending [7:4] enabled [8] CSRs; write (RV_IRQ=1): enabled */
#define TIMECMP     IO(0x20)  /* write: timer source fires when TIME equals this (write clears it) */
#define WAIT        IO(0x24)  /* write: sources; stalls until one is pending */
#define IRQ_TIMER   1u
#define IRQ_UART    2u        /* received byte waiting (level: read them all) */
#define IRQ_CONSOLE 4u        /* console input byte waiting (level) */
#define IRQ_SE      8u        /* secure element command done (clear: write SE STATUS bit 1) */

static inline int irq_present(void) { return (IRQ >> 8) & 1; }

/* CRC unit (RV_CRC=1), reflected, e.g. 0x8408/0x6363 = CRC_A */
#define CRC_POLY    IO(0x28)  /* write: reflected polynomial */
#define CRC_VALUE   IO(0x2C)  /* write: initial value; read: current CRC */
#define CRC_DATA    IO(0x30)  /* write: one byte */
static inline int crc_present(void) { return (IRQ >> 9) & 1; }
static inline uint32_t crc_bytes(uint32_t poly, uint32_t init, const uint8_t *p, uint32_t n)
{
    CRC_POLY = poly;
    CRC_VALUE = init;
    while (n--)
        CRC_DATA = *p++;
    return CRC_VALUE;
}
/* handler: irq_handler() in irq.c (weak) */
static inline void irq_enable(uint32_t sources)
{
    IRQ = sources;
    __asm__ volatile ("csrs mie, %0" :: "r"(0x80u));     /* MTIE */
    __asm__ volatile ("csrsi mstatus, 8");               /* MIE */
}
static inline void irq_off(void) { __asm__ volatile ("csrci mstatus, 8"); }
static inline void irq_on(void)  { __asm__ volatile ("csrsi mstatus, 8"); }
/* timer source fires `clocks` from now (at most 2^25 - 1, 1.24 s at 27 MHz) */
static inline void timer_in(uint32_t clocks) { TIMECMP = (TIME + clocks) & TIME_MASK; }

#endif
