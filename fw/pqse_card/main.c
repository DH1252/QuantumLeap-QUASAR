/* main.c - PN532 card emulation, APDUs to the SE bus */
#include <stddef.h>
#include <stdint.h>
#include "pqse_hw.h"

#define NOINLINE __attribute__((noinline))  /* keep -Os from inlining small helpers everywhere */
#define FW_NAME "pqse_card 1.1"

uint32_t clocks_ms;                         /* clocks per ms, set from CLK_KHZ in main (.bss) */
#define T_BOOT (39u * CLOCKS_MS)            /* PN532 power-up */
#define T_ACK  (155u * CLOCKS_MS)           /* ACK; answer to a quick command */
#define T_RUN  (1000u * CLOCKS_MS)          /* secure element command (its watchdog: 155 ms) */

/* ---- time: TIME wraps after 2^25 clocks (1.24 s at 27 MHz); check timeouts
   at least that often ---- */
typedef struct { uint32_t last, left; } tmo_t;

NOINLINE static void tmo_start(tmo_t *t, uint32_t clocks)
{
    t->last = TIME;
    t->left = clocks;
}

NOINLINE static int tmo_over(tmo_t *t)
{
    uint32_t now = TIME, d = (now - t->last) & TIME_MASK;
    t->last = now;
    if (d >= t->left) {
        t->left = 0;                        /* stays over */
        return 1;
    }
    t->left -= d;
    return 0;
}

/* sleep until a source is pending or t is about to run out
   (< 4096 clocks left: return, TIMECMP could pass before the store) */
NOINLINE static void nap(tmo_t *t, uint32_t sources)
{
    if (t) {
        if (t->left < 4096)
            return;
        timer_in(t->left > 0x1000000u ? 0x1000000u : t->left);
        sources |= IRQ_TIMER;
    }
    WAIT = sources;
}

/* ---- console ---- */
NOINLINE static void con_puts(const char *s)
{
    while (*s)
        CONSOLE = (uint8_t)*s++;
}

NOINLINE static void con_hex(uint32_t v, int digits)
{
    while (digits-- > 0)
        CONSOLE = (uint8_t)"0123456789abcdef"[(v >> (digits << 2)) & 15];
}

/* ---- secure element: one command; 0 done within T_RUN, -1 not ---- */
static int se_run(uint32_t flags, uint32_t cmd, uint32_t *st, uint32_t *cyc)
{
    tmo_t t;
    SE(SE_STATUS) = 2;                      /* clear done of an earlier command */
    SE(SE_CTRL) = ((flags & 1) << 8) | (cmd & 0xFF);
    tmo_start(&t, T_RUN);
    while (!((*st = SE(SE_STATUS)) & 2)) {
        if (tmo_over(&t))
            return -1;
        nap(&t, IRQ_SE);
    }
    *cyc = SE(SE_CYCLES);
    SE(SE_STATUS) = 2;
    return 0;
}

/* ---- command line on the console (board registers 0x7F1 / 0x7F2) ---- */
static char line[64];
static uint32_t llen;
static uint32_t pn_restart;                 /* "restart": abort PN532 waits, start again */
static uint32_t pn_state;                   /* 0 no answer, 1 card emulation, 2 reader */
static uint32_t n_apdu;

static const char *skip(const char *p)
{
    while (*p == ' ')
        p++;
    return p;
}

NOINLINE static int word(const char **pp, const char *w)   /* next word is w: skip it */
{
    const char *p = skip(*pp);
    while (*w && *p == *w) {
        p++;
        w++;
    }
    if (*w || (*p && *p != ' '))
        return 0;
    *pp = p;
    return 1;
}

NOINLINE static int hexnum(const char **pp, uint32_t *v)    /* hex number (0x optional) */
{
    const char *p = skip(*pp);
    uint32_t n = 0, d;
    *v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;
    for (;; p++, n++) {
        if (*p >= '0' && *p <= '9')
            d = (uint32_t)(*p - '0');
        else if ((*p | 0x20) >= 'a' && (*p | 0x20) <= 'f')
            d = (uint32_t)((*p | 0x20) - 'a' + 10);
        else
            break;
        *v = (*v << 4) | d;
    }
    if (n == 0 || (*p && *p != ' '))
        return 0;
    *pp = p;
    return 1;
}

static int hexdig(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c |= 0x20;
    return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

static void sh_exec(const char *p)
{
    uint32_t a, v, n, i, st, cyc;
    if (*skip(p) == 0)
        return;
    if (word(&p, "help")) {
        con_puts("rd A [N], wr A V, run C [1], st, info, restart, crc P I HEX (hex numbers)\n");
    } else if (word(&p, "rd") && hexnum(&p, &a)) {
        n = 1;
        if (*skip(p) && (!hexnum(&p, &n) || n == 0 || n > 32)) {
            con_puts("N: 1 to 32 (hex 1 to 20)\n");
            return;
        }
        for (i = 0; i < n; i++) {
            if ((i & 3) == 0) {
                if (i)
                    con_puts("\n");
                con_hex((a + i) & 0xFFF, 3);
                con_puts(":");
            }
            con_puts(" ");
            con_hex(SE((a + i) & 0xFFF), 8);
        }
        con_puts("\n");
    } else if (word(&p, "wr") && hexnum(&p, &a) && hexnum(&p, &v)) {
        SE(a & 0xFFF) = v;
    } else if (word(&p, "run") && hexnum(&p, &a)) {
        n = 0;
        if (*skip(p) && !hexnum(&p, &n))
            n = 0;
        if (se_run(n, a, &st, &cyc) < 0) {
            con_puts("not done after 1 s\n");
            return;
        }
        con_puts("result ");
        con_hex(st >> 8, 2);
        con_puts(", STATUS ");
        con_hex(st, 8);
        con_puts(", clocks ");
        con_hex(cyc, 8);
        con_puts("\n");
    } else if (word(&p, "st")) {
        con_puts("ID ");
        con_hex(SE(SE_ID), 8);
        con_puts(" VERSION ");
        con_hex(SE(SE_VERSION), 8);
        con_puts(" STATUS ");
        con_hex(SE(SE_STATUS), 8);
        con_puts(" LIFECYCLE ");
        con_hex(SE(0x405), 1);
        con_puts(" CONFIG ");
        con_hex(SE(0x406), 1);
        con_puts("\n");
    } else if (word(&p, "info")) {
        con_puts(FW_NAME ", PN532 ");
        con_puts(pn_state == 0 ? "not answering" : pn_state == 1 ? "emulating a card" : "selected by a reader");
        con_puts(", APDUs ");
        con_hex(n_apdu, 8);
        con_puts(UART_STATUS & 4 ? ", UART overrun\n" : "\n");
    } else if (word(&p, "crc") && hexnum(&p, &a) && hexnum(&p, &v)) {
        int h, l;
        if (!crc_present()) {
            con_puts("no CRC unit (RV_CRC=1)\n");
            return;
        }
        CRC_POLY = a;
        CRC_VALUE = v;
        for (p = skip(p); (h = hexdig(p[0])) >= 0 && (l = hexdig(p[1])) >= 0; p += 2)
            CRC_DATA = (uint32_t)((h << 4) | l);
        con_hex(CRC_VALUE, 8);
        con_puts("\n");
    } else if (word(&p, "restart")) {
        pn_restart = 1;
    } else {
        con_puts("? (help)\n");
    }
}

static void sh_poll(void)                   /* one console byte, if any */
{
    uint32_t v = CONSOLE_IN, c;
    if (!(v & 0x100))
        return;
    c = v & 0xFF;
    if (c == '\r') {
        con_puts("\n");
        line[llen] = 0;
        sh_exec(line);
        llen = 0;
        con_puts("> ");
    } else if (c == 8 || c == 0x7F) {
        if (llen) {
            llen--;
            con_puts("\b \b");
        }
    } else if (c == 3) {                    /* Ctrl-C */
        llen = 0;
        con_puts("^C\n> ");
    } else if (c >= 0x20 && c < 0x7F && llen < sizeof line - 1) {
        line[llen++] = (char)c;
        CONSOLE = c;
    }
}

static void delay(uint32_t clocks)
{
    tmo_t t;
    tmo_start(&t, clocks);
    while (!tmo_over(&t)) {
        sh_poll();
        nap(&t, IRQ_CONSOLE);
    }
}

/* ---- UART to the PN532 ---- */
NOINLINE static void uart_put(uint32_t b)
{
    UART_DATA = b & 0xFF;                   /* store stalls while a byte goes out */
}

/* t = 0: no timeout (command line served meanwhile; -1 after "restart").
   Returns -1 on timeout */
static int uart_get(tmo_t *t)
{
    for (;;) {
        uint32_t v = UART_DATA;
        if (v & 0x100)
            return (int)(v & 0xFF);
        if (t) {
            if (tmo_over(t))
                return -1;
            nap(t, IRQ_UART);
        } else {
            sh_poll();
            if (pn_restart)
                return -1;
            nap(0, IRQ_UART | IRQ_CONSOLE);
        }
    }
}

static void uart_flush(void)
{
    while (UART_DATA & 0x100)
        ;
    UART_STATUS = 4;
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* ---- PN532 frames (UM0701-02): 00 00 FF LEN LCS D4 data DCS 00, extended
   00 00 FF FF FF LENM LENL LCS D4 data DCS 00 ---- */
#define FR_ACK (-1)
#define FR_BAD (-2)
#define FR_TMO (-3)
#define RX_MAX 272                          /* 87 status APDU: up to 264 */
#define TX_MAX (1 + 256 + 2)                /* 8E, response data, SW1 SW2 */

static uint8_t rx[RX_MAX];                  /* last frame after D5: code + 1, payload */
static uint8_t tx[TX_MAX];
#define OUT (tx + 1)                        /* response data */

static void pn_send(const uint8_t *d, uint32_t n)   /* d: command code, parameters */
{
    uint32_t len = n + 1, s = 0xD4, i;
    uart_put(0x00);
    uart_put(0x00);
    uart_put(0xFF);
    if (len < 255) {
        uart_put(len);
        uart_put(-len);
    } else {
        uart_put(0xFF);
        uart_put(0xFF);
        uart_put(len >> 8);
        uart_put(len);
        uart_put(-((len >> 8) + (len & 0xFF)));
    }
    uart_put(0xD4);
    for (i = 0; i < n; i++) {
        uart_put(d[i]);
        s += d[i];
    }
    uart_put(-s);
    uart_put(0x00);
}

/* One frame: FR_ACK, FR_BAD (checksum, length, not from the PN532), FR_TMO,
   or n > 0 bytes after D5 in rx. */
static int pn_recv(tmo_t *t)
{
    int b, prev = 0x55, l0, l1, m, l, c, tfi;
    uint32_t len, i, s;
    for (;;) {                              /* start code 00 FF */
        if ((b = uart_get(t)) < 0)
            return FR_TMO;
        if (prev == 0x00 && b == 0xFF)
            break;
        prev = b;
    }
    if ((l0 = uart_get(t)) < 0 || (l1 = uart_get(t)) < 0)
        return FR_TMO;
    if (l0 == 0x00 && l1 == 0xFF)
        return FR_ACK;
    if (l0 == 0xFF && l1 == 0xFF) {         /* extended: LENM LENL LCS */
        if ((m = uart_get(t)) < 0 || (l = uart_get(t)) < 0 || (c = uart_get(t)) < 0)
            return FR_TMO;
        if (((m + l + c) & 0xFF) != 0)
            return FR_BAD;
        len = ((uint32_t)m << 8) | (uint32_t)l;
    } else {
        if (((l0 + l1) & 0xFF) != 0)
            return FR_BAD;
        len = (uint32_t)l0;
    }
    if (len < 2 || len > RX_MAX + 1)
        return FR_BAD;
    if ((tfi = uart_get(t)) < 0)
        return FR_TMO;
    s = (uint32_t)tfi;
    for (i = 0; i + 1 < len; i++) {
        if ((b = uart_get(t)) < 0)
            return FR_TMO;
        rx[i] = (uint8_t)b;
        s += (uint32_t)b;
    }
    if ((b = uart_get(t)) < 0)              /* DCS */
        return FR_TMO;
    if (((s + (uint32_t)b) & 0xFF) != 0 || tfi != 0xD5)
        return FR_BAD;
    return (int)(len - 1);
}

/* Command: ACK within T_ACK, answer within wait clocks (0: no limit).
   Returns the answer length in rx (rx[0] = code + 1), or FR_BAD. */
static int pn_cmd(const uint8_t *d, uint32_t n, uint32_t wait)
{
    tmo_t t;
    int r;
    pn_send(d, n);
    tmo_start(&t, T_ACK);
    if (pn_recv(&t) != FR_ACK)
        return FR_BAD;
    if (wait) {
        tmo_start(&t, wait);
        r = pn_recv(&t);
    } else {
        r = pn_recv(0);
    }
    if (r < 1 || rx[0] != (uint8_t)(d[0] + 1))
        return FR_BAD;
    return r;
}

/* SAMConfiguration: normal mode, 1 s timeout, IRQ pin used */
static const uint8_t c_sam[] = { 0x14, 0x01, 0x14, 0x01 };
/* SetParameters 34h: automatic ATR_RES and RATS, ISO 14443-4 PICC emulation */
static const uint8_t c_par[] = { 0x12, 0x34 };
/* TgInitAsTarget: passive PICC only, SENS_RES 0004, NFCID1 123456, SEL_RES 20h
   (ISO 14443-4), no FeliCa or DEP parameters, no general or historical bytes */
static const uint8_t c_init[] = {
    0x8C, 0x05, 0x04, 0x00, 0x12, 0x34, 0x56, 0x20,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,     /* FeliCa, 18 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                             /* NFCID3, 10 */
    0, 0                                                      /* Gt, Tk */
};
static const uint8_t c_get[] = { 0x86 };    /* TgGetData */

static int pn_start(void)                   /* wake-up, SAMConfiguration, SetParameters */
{
    uint32_t i;
    uart_flush();
    uart_put(0x55);
    uart_put(0x55);
    for (i = 0; i < 14; i++)
        uart_put(0x00);
    if (pn_cmd(c_sam, sizeof c_sam, T_ACK) < 0 || pn_cmd(c_par, sizeof c_par, T_ACK) < 0)
        return -1;
    return 0;
}

/* ---- APDUs ---- */
static const uint8_t aid[7] = { 0xF0, 0x50, 0x51, 0x53, 0x45, 0x00, 0x01 };
static uint32_t selected;

NOINLINE static uint32_t sw(uint32_t n, uint32_t code)   /* append SW after n data bytes; returns response length */
{
    OUT[n] = (uint8_t)(code >> 8);
    OUT[n + 1] = (uint8_t)code;
    return n + 2;
}

static uint32_t cmd_read(uint32_t w, uint32_t le)
{
    uint32_t nw = (le + 3) >> 2, i;
    if (w + nw > SE_WORDS)
        return sw(0, 0x6B00);
    for (i = 0; i < nw; i++)
        put32(OUT + (i << 2), SE(w + i));
    return sw(le, 0x9000);
}

static uint32_t cmd_write(uint32_t w, const uint8_t *d, uint32_t lc)
{
    uint32_t nw = lc >> 2, i;
    if (w + nw > SE_WORDS)
        return sw(0, 0x6B00);
    for (i = 0; i < nw; i++)
        SE(w + i) = get32(d + (i << 2));
    return sw(0, 0x9000);
}

static uint32_t cmd_run(uint32_t p1, uint32_t cmd)
{
    uint32_t st, cyc;
    if (se_run(p1, cmd, &st, &cyc) < 0)
        return sw(0, 0x6400);
    put32(OUT, st);
    put32(OUT + 4, cyc);
    return sw(8, 0x9000);
}

static uint32_t cmd_bus(const uint8_t *d, uint32_t n)
{
    uint32_t i = 0, k = 0, a, c;
    while (i < n) {
        c = d[i++];
        if (c == 'P') {
            if (k + 1 > 256)
                return sw(0, 0x6700);
            OUT[k++] = 'K';
        } else if (c == 'W') {
            if (i + 6 > n)
                break;
            if (k + 1 > 256)
                return sw(0, 0x6700);
            a = ((uint32_t)d[i] | ((uint32_t)d[i + 1] << 8)) & 0xFFF;
            SE(a) = get32(d + i + 2);
            i += 6;
            OUT[k++] = 'K';
        } else if (c == 'R') {
            if (i + 2 > n)
                break;
            if (k + 4 > 256)
                return sw(0, 0x6700);
            a = ((uint32_t)d[i] | ((uint32_t)d[i + 1] << 8)) & 0xFFF;
            i += 2;
            put32(OUT + k, SE(a));
            k += 4;
        }                                   /* other bytes ignored, as by the decoder */
    }
    return sw(k, 0x9000);
}

/* handle one APDU, response in OUT, returns its length (see README) */
static uint32_t apdu(const uint8_t *a, uint32_t n)
{
    uint32_t lc = 0, le = 0, has_le = 0, i, w;
    const uint8_t *d = a + 5;
    if (n < 4)
        return sw(0, 0x6700);
    if (n == 5) {                           /* case 2 */
        le = a[4] ? a[4] : 256;
        has_le = 1;
    } else if (n > 5) {                     /* case 3 / 4, short length only */
        lc = a[4];
        if (lc == 0)
            return sw(0, 0x6700);
        if (n == 6 + lc) {
            le = a[5 + lc] ? a[5 + lc] : 256;
            has_le = 1;
        } else if (n != 5 + lc) {
            return sw(0, 0x6700);
        }
    }
    if (a[0] == 0x00 && a[1] == 0xA4) {     /* SELECT */
        selected = 0;
        if (a[2] != 0x04 || lc != sizeof aid)
            return sw(0, 0x6A82);
        for (i = 0; i < sizeof aid; i++)
            if (d[i] != aid[i])
                return sw(0, 0x6A82);
        selected = 1;
        return sw(0, 0x9000);
    }
    if (a[0] != 0x80)
        return sw(0, 0x6E00);
    if (!selected)
        return sw(0, 0x6985);
    w = ((uint32_t)a[2] << 8) | a[3];
    switch (a[1]) {
    case 0xB0:
        return has_le ? cmd_read(w, le) : sw(0, 0x6700);
    case 0xD0:
        return (lc == 0 || (lc & 3)) ? sw(0, 0x6700) : cmd_write(w, d, lc);
    case 0xC0:
        return cmd_run(a[2], a[3]);
    case 0x10:
        return cmd_bus(d, lc);
    default:
        return sw(0, 0x6D00);
    }
}

/* serve APDUs until the reader releases (0) or the PN532 fails (-1) */
static int serve(void)
{
    int r;
    uint32_t n;
    for (;;) {
        r = pn_cmd(c_get, sizeof c_get, 0); /* TgGetData: next APDU */
        if (r < 0)
            return -1;
        if (r < 2 || rx[1] != 0x00)         /* released (29h) or RF error */
            return 0;
        n = apdu(rx + 2, (uint32_t)r - 2);
        n_apdu++;
        tx[0] = 0x8E;                       /* TgSetData */
        r = pn_cmd(tx, n + 1, T_ACK);
        if (r < 0)
            return -1;
        if (r < 2 || rx[1] != 0x00)
            return 0;
    }
}

int main(void)
{
    uint32_t silent = 0;                    /* "no answer" printed once until it answers */
    clocks_ms = CLK_KHZ;                    /* bitstream clock (CLK_MHZ) */
    if (clocks_ms == 0)
        clocks_ms = CLK_KHZ_DEFAULT;
    con_puts("\n" FW_NAME "\n");
    for (;;) {
        LEDS = 0;
        pn_state = 0;
        delay(T_BOOT);
        pn_restart = 0;
        if (pn_start() < 0) {
            if (!silent)
                con_puts("pn532: no answer\n");
            silent = 1;
            continue;
        }
        silent = 0;
        con_puts("pn532: ready\n");
        for (;;) {                          /* card emulation, until the PN532 fails */
            LEDS = 1;
            pn_state = 1;
            if (pn_cmd(c_init, sizeof c_init, 0) < 0)   /* waits for a reader */
                break;
            LEDS = 3;
            pn_state = 2;
            selected = 0;
            con_puts("reader: mode ");
            con_hex(rx[1], 2);
            con_puts("\n");
            if (serve() < 0)
                break;
            con_puts("reader: gone\n");
        }
        con_puts("pn532: restart\n");
    }
}

/* Called by the compiler for copies and clears; volatile keeps the loops from
   being turned back into calls to themselves. */
void *memset(void *dst, int c, size_t n)
{
    volatile uint8_t *p = dst;
    while (n--)
        *p++ = (uint8_t)c;
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    volatile uint8_t *p = dst;
    const uint8_t *q = src;
    while (n--)
        *p++ = *q++;
    return dst;
}
