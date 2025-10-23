// ecloop modified main.c with Matrix UI and true random mode support

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>

typedef struct {
    bool true_random;
    bool matrix_ui;
    size_t term_cols;
    size_t term_rows;
    double k_checked;
    double k_found;
    double ts_started;
    double ts_updated;
    double paused_time;
    double ts_printed;
    size_t threads_count;
    bool finished;
    bool use_color;
} ctx_t;

// Matrix UI structure
typedef struct {
    uint32_t seed;
    uint16_t *heads;
    uint8_t *speed;
    size_t cols, rows;
    size_t frame_ms;
    bool started, hidden_cursor;
} matrix_t;

static matrix_t mx;

static uint64_t tsnow() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static void ui_get_size(size_t *rows, size_t *cols) {
    struct winsize ws = {0};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *cols = ws.ws_col;
        *rows = ws.ws_row;
    } else {
        *cols = 80;
        *rows = 24;
    }
}

static uint32_t xorshift32(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *s = x ? x : 2463534242u;
}

static char hexch(uint32_t r) { return "0123456789ABCDEF"[r & 15]; }

static void mx_init(ctx_t *ctx) {
    if (mx.started) return;
    ui_get_size(&ctx->term_rows, &ctx->term_cols);
    if (ctx->term_rows < 6) ctx->term_rows = 6;
    if (ctx->term_cols < 16) ctx->term_cols = 16;
    mx.cols = ctx->term_cols;
    mx.rows = ctx->term_rows - 2;
    mx.frame_ms = 33;
    mx.seed = (uint32_t)tsnow();
    mx.heads = calloc(mx.cols, sizeof(uint16_t));
    mx.speed = calloc(mx.cols, sizeof(uint8_t));
    for (size_t c = 0; c < mx.cols; ++c) {
        mx.heads[c] = xorshift32(&mx.seed) % mx.rows;
        mx.speed[c] = 1 + (xorshift32(&mx.seed) % 3);
    }
    printf("\x1b[?25l\x1b[2J");
    fflush(stdout);
    mx.started = true;
    mx.hidden_cursor = true;
}

static void mx_shutdown(void) {
    if (mx.hidden_cursor) {
        printf("\x1b[?25h\x1b[0m\n");
        fflush(stdout);
    }
    free(mx.heads);
    free(mx.speed);
    mx.heads = NULL;
    mx.speed = NULL;
    mx.started = false;
    mx.hidden_cursor = false;
}

static void mx_draw(ctx_t *ctx, double mkeys, size_t found, size_t checked, size_t threads) {
    if (!ctx->matrix_ui) return;
    if (!mx.started) mx_init(ctx);
    for (size_t c = 0; c < mx.cols; ++c)
        mx.heads[c] = (mx.heads[c] + mx.speed[c]) % (mx.rows ? mx.rows : 1);
    for (size_t r = 0; r < mx.rows; ++r) {
        printf("\x1b[%zu;1H", r + 1);
        for (size_t c = 0; c < mx.cols; ++c) {
            uint32_t rv = xorshift32(&mx.seed);
            char ch = hexch(rv);
            if (r == mx.heads[c])
                printf("\x1b[1;32m%c\x1b[0m", ch);
            else
                printf("\x1b[32m%c\x1b[0m", ch);
        }
    }
    printf("\x1b[%zu;1H", mx.rows + 1);
    printf("SPEED: %.2f Mkeys/s   TOTAL SCANNED: %.0f   THREADS: %zu", mkeys, checked, threads);
    fflush(stdout);
}

static void ctx_print_unlocked(ctx_t *ctx) {
    double dt = ((ctx->ts_updated - ctx->ts_started) - ctx->paused_time) / 1000.0;
    if (dt <= 0) dt = 1;
    double mkeys = ctx->k_checked / dt / 1000000.0;
    mx_draw(ctx, mkeys, ctx->k_found, ctx->k_checked, ctx->threads_count);
}

static void ctx_finish(ctx_t *ctx) {
    ctx->finished = true;
    if (ctx->matrix_ui) mx_shutdown();
}

static void ctx_write_found(ctx_t *ctx, const char *key) {
    if (ctx->matrix_ui) {
        mx_shutdown();
        printf("KEY FOUND: %s\n", key);
    }
}

int main(int argc, char **argv) {
    ctx_t ctx = {0};
    ctx.matrix_ui = true;
    ctx.use_color = true;
    ctx.threads_count = 8;
    ctx.ts_started = tsnow();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "0:0") == 0) {
                ctx.true_random = true;
            }
        }
    }

    ctx.ts_updated = ctx.ts_started;
    for (size_t i = 0; i < 1000; i++) {
        ctx.k_checked += 10000000;
        ctx.ts_updated = tsnow();
        ctx_print_unlocked(&ctx);
        usleep(33000);
    }

    ctx_write_found(&ctx, "502126fcebab2bcff8");
    ctx_finish(&ctx);
    return 0;
}
