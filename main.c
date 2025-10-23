// Copyright (c) vladkens
// https://github.com/vladkens/ecloop
// Licensed under the MIT License.

#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "lib/addr.c"
#include "lib/bench.c"
#include "lib/ecc.c"
#include "lib/utils.c"

// === Matrix UI ===
#include <sys/ioctl.h>
#include <termios.h>

typedef struct {
  uint32_t seed;
  uint16_t *heads;
  uint8_t  *speed;
  size_t cols, rows;
  size_t frame_ms;
  bool started, hidden_cursor;
} matrix_t;

static matrix_t mx;

static inline uint64_t tsnow_ms_inline() {
  return tsnow();
}

static void ui_get_size(size_t *rows, size_t *cols) {
  struct winsize ws = {0};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
    *cols = ws.ws_col;
    *rows = ws.ws_row;
  } else {
    *cols = 80; *rows = 24;
  }
}

static uint32_t xorshift32(uint32_t *s) {
  uint32_t x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return *s = x ? x : 2463534242u;
}

static char hexch(uint32_t r) { return "0123456789ABCDEF"[r & 15]; }

static void mx_init(ctx_t *ctx) {
  if (mx.started) return;
  size_t rows=0, cols=0;
  ui_get_size(&rows, &cols);
  if (rows < 6) rows = 6;
  if (cols < 16) cols = 16;
  mx.cols = cols;
  mx.rows = rows - 2; // reserve 2 lines for stats
  mx.frame_ms = 33;   // ~30 FPS
  mx.seed = (uint32_t)tsnow_ms_inline();
  mx.heads = (uint16_t*)calloc(mx.cols, sizeof(uint16_t));
  mx.speed = (uint8_t*)calloc(mx.cols, sizeof(uint8_t));
  for (size_t c = 0; c < mx.cols; ++c) {
    mx.heads[c] = xorshift32(&mx.seed) % mx.rows;
    mx.speed[c] = 1 + (xorshift32(&mx.seed) % 3);
  }
  if (ctx->use_color) printf("\x1b[?25l\x1b[2J");
  fflush(stdout);
  mx.started = true;
  mx.hidden_cursor = true;
}

static void mx_shutdown(void) {
  if (mx.hidden_cursor) {
    printf("\x1b[?25h\x1b[0m\n");
    fflush(stdout);
  }
  free(mx.heads); free(mx.speed);
  mx.heads = NULL; mx.speed = NULL;
  mx.started = false; mx.hidden_cursor = false;
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
      if (r == mx.heads[c]) {
        if (ctx->use_color) printf("\x1b[1;32m%c\x1b[0m", ch); else putchar(ch);
      } else {
        if (ctx->use_color) printf("\x1b[32m%c\x1b[0m", ch); else putchar(ch);
      }
    }
  }
  printf("\x1b[%zu;1H", mx.rows + 1);
  printf("SPEED: %.2f Mkeys/s   TOTAL SCANNED: %'zu   THREADS: %zu", mkeys, checked, threads);
  fflush(stdout);
}

#define VERSION "0.5.0"
#define MAX_JOB_SIZE 1024 * 1024 * 2

// … the rest of the original includes, types, macros …

enum Cmd { CMD_NIL, CMD_ADD, CMD_MUL, CMD_RND };

typedef struct ctx_t {
  enum Cmd cmd;
  pthread_mutex_t lock;
  size_t threads_count;
  pthread_t *threads;
  size_t k_checked;
  size_t k_found;
  bool check_addr33;
  bool check_addr65;
  bool use_endo;

  FILE *outfile;
  bool quiet;
  bool use_color;

  bool finished;       // true if the program is exiting
  bool paused;         // true if the program is paused
  size_t ts_started;   // timestamp of start
  size_t ts_updated;   // timestamp of last update
  size_t ts_printed;   // timestamp of last print
  size_t ts_paused_at; // timestamp when paused
  size_t paused_time;  // time spent in paused state

  // UI and mode
  bool true_random;     // -d 0:0 enables true random search windowing
  bool matrix_ui;       // enable Matrix-style terminal animation

  // filter file 
  hlist_t blf;
  h160_t *to_find_hashes;
  size_t to_find_count;

  // cmd add
  fe range_s;  // search range start
  fe range_e;  // search range end
  fe stride_k; // precomputed stride key (step for G-points, 2^offset)
  pe stride_p; // precomputed stride point (G * pk)
  pe gpoints[GROUP_INV_SIZE];
  size_t job_size;

  // cmd mul
  queue_t queue;
  bool raw_text;

  // cmd rnd
  bool has_seed;
  u32 ord_offs; // offset (order) of range to search
  u32 ord_size; // size (span) in range to search
} ctx_t;

// … all original helper functions, bloom filter loaders, etc …

// note: this function is not thread-safe; use mutex lock before calling
void ctx_print_unlocked(ctx_t *ctx) {
  // Matrix UI replaces single-line progress if enabled
  int64_t effective_time = (int64_t)(ctx->ts_updated - ctx->ts_started) - (int64_t)ctx->paused_time;
  double dt = MAX(1, effective_time) / 1000.0;
  double it = ctx->k_checked / dt / 1000000.0;

  if (ctx->matrix_ui && !ctx->quiet) {
    mx_draw(ctx, it, ctx->k_found, ctx->k_checked, ctx->threads_count);
    return;
  }

  char *msg = ctx->finished ? "" : (ctx->paused ? " ('r' – resume)" : " ('p' – pause)");
  term_clear_line();
  fprintf(stderr, "%.2fs ~ %.2f Mkeys/s ~ %'zu / %'zu%s%c",
          dt, it, ctx->k_found, ctx->k_checked, msg, ctx->finished ? '\n' : '\r');
  fflush(stderr);
}

void ctx_print_status(ctx_t *ctx) {
  pthread_mutex_lock(&ctx->lock);
  ctx_print_unlocked(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void ctx_check_paused(ctx_t *ctx) {
  if (ctx->paused) {
    while (ctx->paused) usleep(100000);
  }
}

void ctx_update(ctx_t *ctx, size_t k_checked) {
  size_t ts = tsnow();

  pthread_mutex_lock(&ctx->lock);
  bool need_print = (ts - ctx->ts_printed) >= 33; // smoother refresh for Matrix UI
  ctx->k_checked += k_checked;
  ctx->ts_updated = ts;
  if (need_print) {
    ctx->ts_printed = ts;
    ctx_print_unlocked(ctx);
  }
  pthread_mutex_unlock(&ctx->lock);

  ctx_check_paused(ctx);
}

void ctx_finish(ctx_t *ctx) {
  pthread_mutex_lock(&ctx->lock);
  ctx->finished = true;
  if (ctx->matrix_ui) mx_shutdown();
  ctx_print_unlocked(ctx);
  if (ctx->outfile != NULL) fclose(ctx->outfile);
  pthread_mutex_unlock(&ctx->lock);
}

void ctx_write_found(ctx_t *ctx, const char *label, const h160_t hash, const fe pk) {
  pthread_mutex_lock(&ctx->lock);

  if (ctx->matrix_ui) { mx_shutdown(); printf("KEY FOUND: "); fflush(stdout); } 
  if (!ctx->quiet) {
    term_clear_line();
    printf("%s: %08x%08x%08x%08x%08x <- %016llx%016llx%016llx%016llx\n", //
           label, hash[0], hash[1], hash[2], hash[3], hash[4],           //
           pk[3], pk[2], pk[1], pk[0]);
  }

  if (ctx->outfile != NULL) {
    fprintf(ctx->outfile, "%s\t%08x%08x%08x%08x%08x\t%016llx%016llx%016llx%016llx\n", //
            label, hash[0], hash[1], hash[2], hash[3], hash[4],                       //
            pk[3], pk[2], pk[1], pk[0]);
    fflush(ctx->outfile);
  }

  ctx->k_found += 1;
  ctx_print_unlocked(ctx);

  pthread_mutex_unlock(&ctx->lock);
}

// MARK: CMD_RND

void gen_random_range(ctx_t *ctx, const fe a, const fe b) {
  if (ctx->true_random) {
    // ignore requested offset/size specifics; pick a random start anywhere and build a small window
    fe_rand_range(ctx->range_s, a, b, !ctx->has_seed);
    fe_clone(ctx->range_e, ctx->range_s);
    u32 size = ctx->ord_size ? ctx->ord_size : 32;
    u32 offs = rand64(!ctx->has_seed) % (256 - size);
    for (u32 i = offs; i < (offs + size); ++i) {
      ctx->range_s[i / 64] &= ~(1ULL << (i % 64));
      ctx->range_e[i / 64] |= 1ULL << (i % 64);
    }
    // clamp to bounds
    if (fe_cmp(ctx->range_s, a) <= 0) fe_clone(ctx->range_s, a);
    if (fe_cmp(ctx->range_e, b) >= 0) fe_clone(ctx->range_e, b);
    return;
  }

  fe_rand_range(ctx->range_s, a, b, !ctx->has_seed);
  fe_clone(ctx->range_e, ctx->range_s);
  for (u32 i = ctx->ord_offs; i < (ctx->ord_offs + ctx->ord_size); ++i) {
    ctx->range_s[i / 64] &= ~(1ULL << (i % 64));
    ctx->range_e[i / 64] |= 1ULL << (i % 64);
  }

  // put in bounds
  if (fe_cmp(ctx->range_s, a) <= 0) fe_clone(ctx->range_s, a);
  if (fe_cmp(ctx->range_e, b) >= 0) fe_clone(ctx->range_e, b);
}

void cmd_rnd(ctx_t *ctx) {
  ctx->ord_offs = MIN(ctx->ord_offs, 255 - ctx->ord_size);
  if (!ctx->matrix_ui) printf("[RANDOM MODE] offs: %d ~ bits: %d\n\n", ctx->ord_offs, ctx->ord_size);

  ctx_precompute_gpoints(ctx);
  ctx->job_size = MAX_JOB_SIZE;
  ctx->ts_started = tsnow(); // actual start time

  fe range_s, range_e;
  fe_clone(range_s, ctx->range_s);
  fe_clone(range_e, ctx->range_e);

  size_t last_c = 0, last_f = 0, s_time = 0;
  while (true) {
    last_c = ctx->k_checked;
    last_f = ctx->k_found;
    s_time = tsnow();

    gen_random_range(ctx, range_s, range_e);
    if (!ctx->matrix_ui) {
      print_range_mask(ctx->range_s, ctx->ord_size, ctx->ord_offs, ctx->use_color);
      print_range_mask(ctx->range_e, ctx->ord_size, ctx->ord_offs, ctx->use_color);
      ctx_print_status(ctx);
    }

    // if full range is used, skip break after first iteration
    bool is_full = fe_cmp(ctx->range_s, range_s) == 0 && fe_cmp(ctx->range_e, range_e) == 0;

    for (size_t i = 0; i < ctx->threads_count; ++i) {
      pthread_create(&ctx->threads[i], NULL, cmd_add_worker, ctx);
    }

    for (size_t i = 0; i < ctx->threads_count; ++i) {
      pthread_join(ctx->threads[i], NULL);
    }

    size_t dc = ctx->k_checked - last_c, df = ctx->k_found - last_f;
    double dt = MAX((tsnow() - s_time), 1ul) / 1000.0;
    if (!ctx->matrix_ui) printf("%'zu / %'zu ~ %.1fs\n\n", df, dc, dt);

    if (is_full) break;
  }

  ctx_finish(ctx);
}

// MARK: args helpers

void load_offs_size(ctx_t *ctx, args_t *args) {
  const u32 MIN_SIZE = 20;
  const u32 MAX_SIZE = 64;

  u32 range_bits = fe_bitlen(ctx->range_e);
  u32 default_bits = range_bits < 32 ? MAX(MIN_SIZE, range_bits) : 32;
  u32 max_offs = MAX(1ul, MAX(MIN_SIZE, range_bits) - default_bits);

  char *raw = arg_str(args, "-d");
  if (!raw && ctx->cmd == CMD_RND) {
    ctx->ord_offs = rand64(!ctx->has_seed) % max_offs;
    ctx->ord_size = default_bits;
    return;
  }

  if (!raw) {
    ctx->ord_offs = 0;
    ctx->ord_size = default_bits;
    return;
  }

  if (raw && strcmp(raw, "0:0") == 0) { ctx->true_random = true; ctx->ord_offs = 0; ctx->ord_size = 32; return; }

  char *sep = strchr(raw, ':');
  if (!sep) {
    fprintf(stderr, "invalid offset:size format, use format: -d 128:32\n");
    exit(1);
  }

  *sep = 0;
  u32 tmp_offs = atoi(raw);
  u32 tmp_size = atoi(sep + 1);

  if (tmp_offs > 255) {
    fprintf(stderr, "invalid offset, max is 255\n");
    exit(1);
  }

  if (tmp_size < MIN_SIZE || tmp_size > MAX_SIZE) {
    fprintf(stderr, "invalid size, min is %d and max is %d\n", MIN_SIZE, MAX_SIZE);
    exit(1);
  }

  ctx->ord_offs = MIN(max_offs, tmp_offs);
  ctx->ord_size = tmp_size;
}

// MARK: main

void usage(const char *name) {
  printf("Usage:\n");
  printf("  %s <command> [options]\n\n", name);
  printf("Commands:\n");
  printf("  add            - scan random private keys for addresses\n");
  printf("  mul            - multiply private keys by G\n");
  printf("  rnd            - random search mode (windowed)\n\n");
  printf("Options:\n");
  printf("  -f <file>      - filter file (.blf or hash list)\n");
  printf("  -o <file>      - output file for matches\n");
  printf("  -t <threads>   - number of threads (default: cpu cores)\n");
  printf("  -a <addr_type> - address type to search: c - addr33, u - addr65 (default: c)\n");
  printf("  -r <range>     - search range in hex format (example: 8000:ffff, default all)\n");
  printf("  -d <offs:size> - bit offset and size for search (example: 128:32, default: 0:32). Use 0:0 for true-random window\n");
  printf("  -q             - quiet mode (no output to stdout; -o required)\n");
  printf("  -endo          - use endomorphism for add command (faster)\n");
  printf("\n");
}

void init(ctx_t *ctx, args_t *args) {
  // check other commands first
  if (args->argc > 1) {
    if (strcmp(args->argv[1], "blf-gen") == 0) return blf_gen(args);
    if (strcmp(args->argv[1], "blf-check") == 0) return blf_check(args);
    if (strcmp(args->argv[1], "bench") == 0) return run_bench();
    if (strcmp(args->argv[1], "bench-gtable") == 0) return run_bench_gtable();
    if (strcmp(args->argv[1], "mult-verify") == 0) return mult_verify();
  }

  ctx->use_color = isatty(fileno(stdout));
  ctx->matrix_ui = ctx->use_color && !args_bool(args, "-q");
  ctx->true_random = false;

  ctx->cmd = CMD_NIL; // default show help
  if (args->argc > 1) {
    if (strcmp(args->argv[1], "add") == 0) ctx->cmd = CMD_ADD;
    if (strcmp(args->argv[1], "mul") == 0) ctx->cmd = CMD_MUL;
    if (strcmp(args->argv[1], "rnd") == 0) ctx->cmd = CMD_RND;
  }

  if (ctx->cmd == CMD_NIL) {
    usage(args->argv[0]);
    exit(0);
  }

  // … original init code continues unchanged …
  // sets ranges, loads filter, threads, prints header, etc.

  // end of init
}

int main(int argc, const char **argv) {
  // https://stackoverflow.com/a/11695246
  setlocale(LC_NUMERIC, ""); // for comma separated numbers
  args_t args = {argc, argv};

  ctx_t ctx = {0};
  init(&ctx, &args);

  signal(SIGINT, handle_sigint); // Keep last progress line on Ctrl-C
  tty_init(tty_cb, &ctx);        // override tty to handle pause/resume

  if (ctx.cmd == CMD_ADD) cmd_add(&ctx);
  if (ctx.cmd == CMD_MUL) cmd_mul(&ctx);
  if (ctx.cmd == CMD_RND) cmd_rnd(&ctx);

  return 0;
}
