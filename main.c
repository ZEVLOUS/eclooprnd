// Copyright (c) vladkens
// https://github.com/vladkens/ecloop
// Licensed under the MIT License.

// MATRIX-UI EDITION for Termux (Android):
// - Replaces progress box with fullscreen Matrix rain
// - Top-pinned live stats: SPEED, TOTAL SCANNED, THREADS
// - Smooth animation with per-column speeds and green fading shades
// - No flicker: cursor repositioning (no full clears per frame)
// - Clean stop on hit: prints "KEY FOUND: <key>" and exits
// - Adds true random mode: -d 0:0  (continuous random search)
//
// Build (Termux):
//   gcc -O2 -pthread -o ecloop_matrix ecloop_matrix.c
//
// Usage is same as original; core search logic untouched.

#define _XOPEN_SOURCE 700
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "lib/addr.c"
#include "lib/bench.c"
#include "lib/ecc.c"
#include "lib/utils.c"

#define VERSION "0.5.0-matrix"
#define MAX_JOB_SIZE 1024 * 1024 * 2
#define GROUP_INV_SIZE 2048ul
#define MAX_LINE_SIZE 1025

static_assert(GROUP_INV_SIZE % HASH_BATCH_SIZE == 0,
              "GROUP_INV_SIZE must be divisible by HASH_BATCH_SIZE");

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

  // UI / Matrix renderer
  pthread_t ui_thread;
  bool ui_running;
  bool stop_animation;
  double speed_mkeys;  // instantaneous / smoothed
  // store terminal size cached by UI thread
  int term_cols;
  int term_rows;

  // hit handling
  bool key_found_flag;
  fe found_pk;
  char found_label[16];

  // filter file (bloom filter or hashes to search)
  h160_t *to_find_hashes;
  size_t to_find_count;
  blf_t blf;

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
  bool true_random; // -d 0:0 => continuous true random
  u32 ord_offs;     // offset (order) of range to search
  u32 ord_size;     // size (span) in range to search
} ctx_t;

// ---------- Small ANSI helpers ----------

#define ESC "\x1b["
#define CSI(x) ESC x
#define HIDE_CURSOR CSI("?25l")
#define SHOW_CURSOR CSI("?25h")
#define CLEAR_SCREEN CSI("2J")
#define RESET_COLORS CSI("0m")

static inline void ansi_move(int row, int col) {
  // 1-based
  printf(ESC "%d;%dH", row, col);
}

static inline void ansi_clear_line() { fputs(CSI("2K"), stdout); }

// Green shades (256-color) to simulate Matrix fade
// A sequence of greenish codes from dim to bright
static const int GREEN_SHADE[] = { 22, 28, 34, 40, 46, 82, 118, 154, 190, 46 };
static const int GREEN_LEVELS = sizeof(GREEN_SHADE) / sizeof(GREEN_SHADE[0]);

static inline void set_fg256(int code) {
  printf(ESC "38;5;%dm", code);
}

static inline void save_cursor() { fputs(CSI("s"), stdout); }
static inline void restore_cursor() { fputs(CSI("u"), stdout); }

// ---------- Filter loading (unchanged) ----------

void load_filter(ctx_t *ctx, const char *filepath) {
  if (!filepath) {
    fprintf(stderr, "missing filter file\n");
    exit(1);
  }

  FILE *file = fopen(filepath, "rb");
  if (!file) {
    fprintf(stderr, "failed to open filter file: %s\n", filepath);
    exit(1);
  }

  char *ext = strrchr(filepath, '.');
  if (ext != NULL && strcmp(ext, ".blf") == 0) {
    if (!blf_load(filepath, &ctx->blf)) exit(1);
    fclose(file);
    return;
  }

  size_t hlen = sizeof(u32) * 5;
  assert(hlen == sizeof(h160_t));
  size_t capacity = 32;
  size_t size = 0;
  u32 *hashes = malloc(capacity * hlen);

  hex40 line;
  while (fgets(line, sizeof(line), file)) {
    if (strlen(line) != sizeof(line) - 1) continue;

    if (size >= capacity) {
      capacity *= 2;
      hashes = realloc(hashes, capacity * hlen);
    }

    for (size_t j = 0; j < sizeof(line) - 1; j += 8) {
      sscanf(line + j, "%8x", &hashes[size * 5 + j / 8]);
    }

    size += 1;
  }

  fclose(file);
  qsort(hashes, size, hlen, compare_160);

  // remove duplicates
  size_t unique_count = 0;
  for (size_t i = 1; i < size; ++i) {
    if (memcmp(&hashes[unique_count * 5], &hashes[i * 5], hlen) != 0) {
      unique_count++;
      memcpy(&hashes[unique_count * 5], &hashes[i * 5], hlen);
    }
  }

  ctx->to_find_hashes = (h160_t *)hashes;
  ctx->to_find_count = unique_count + 1;

  // generate in-memory bloom filter
  ctx->blf.size = ctx->to_find_count * 2;
  ctx->blf.bits = malloc(ctx->blf.size * sizeof(u64));
  for (size_t i = 0; i < ctx->to_find_count; ++i) blf_add(&ctx->blf, hashes + i * 5);
}

// ---------- Status accounting (modified to avoid old progress box) ----------

static inline void ctx_recalc_speed(ctx_t *ctx, size_t k_checked_inc) {
  // smooth EMA on instantaneous rate over last ~200ms windows
  size_t ts = tsnow();
  double elapsed_ms = MAX(1, (int64_t)ts - (int64_t)ctx->ts_updated);
  double inst_mkeys = (k_checked_inc / (elapsed_ms / 1000.0)) / 1e6;
  // EMA alpha
  double alpha = 0.25;
  if (ctx->speed_mkeys <= 0.0) ctx->speed_mkeys = inst_mkeys;
  else ctx->speed_mkeys = alpha * inst_mkeys + (1.0 - alpha) * ctx->speed_mkeys;
  ctx->ts_updated = ts;
}

void ctx_update(ctx_t *ctx, size_t k_checked_inc) {
  pthread_mutex_lock(&ctx->lock);
  ctx->k_checked += k_checked_inc;
  ctx_recalc_speed(ctx, k_checked_inc);
  pthread_mutex_unlock(&ctx->lock);

  if (ctx->paused) {
    while (ctx->paused) usleep(100000);
  }
}

void ctx_finish(ctx_t *ctx) {
  pthread_mutex_lock(&ctx->lock);
  ctx->finished = true;
  // stop animation thread
  ctx->stop_animation = true;
  pthread_mutex_unlock(&ctx->lock);

  if (ctx->ui_running) {
    pthread_join(ctx->ui_thread, NULL);
  }
  if (ctx->outfile != NULL) fclose(ctx->outfile);
}

// ---------- Hit handling (output simplified) ----------

bool ctx_check_hash(ctx_t *ctx, const h160_t h) {
  // bloom filter only mode
  if (ctx->to_find_hashes == NULL) {
    return blf_has(&ctx->blf, h);
  }

  // check by hashes list
  if (!blf_has(&ctx->blf, h)) return false; // fast check with bloom filter

  // if bloom filter check passed, do full check
  h160_t *rs = bsearch(h, ctx->to_find_hashes, ctx->to_find_count, sizeof(h160_t), compare_160);
  return rs != NULL;
}

void ctx_write_found(ctx_t *ctx, const char *label, const h160_t hash, const fe pk) {
  // UI: don't spam stdout during run; just record and stop
  pthread_mutex_lock(&ctx->lock);

  if (ctx->outfile != NULL) {
    fprintf(ctx->outfile, "%s\t%08x%08x%08x%08x%08x\t%016llx%016llx%016llx%016llx\n",
            label, hash[0], hash[1], hash[2], hash[3], hash[4],
            pk[3], pk[2], pk[1], pk[0]);
    fflush(ctx->outfile);
  }

  ctx->k_found += 1;
  ctx->key_found_flag = true;
  strncpy(ctx->found_label, label, sizeof(ctx->found_label)-1);
  fe_clone(ctx->found_pk, pk);

  // signal renderer to stop
  ctx->stop_animation = true;

  pthread_mutex_unlock(&ctx->lock);
}

// ---------- Precompute & core add/mul/rnd logic (unchanged except prints removed) ----------

void ctx_precompute_gpoints(ctx_t *ctx) {
  fe_set64(ctx->stride_k, 1);
  fe_shiftl(ctx->stride_k, ctx->ord_offs);

  fe t;
  fe_modn_add_stride(t, FE_ZERO, ctx->stride_k, GROUP_INV_SIZE);
  ec_jacobi_mulrdc(&ctx->stride_p, &G1, t);

  pe g1, g2;
  ec_jacobi_mulrdc(&g1, &G1, ctx->stride_k);
  ec_jacobi_dblrdc(&g2, &g1);

  size_t hsize = GROUP_INV_SIZE / 2;

  pe_clone(ctx->gpoints + 0, &g1);
  pe_clone(ctx->gpoints + 1, &g2);
  for (size_t i = 2; i < hsize; ++i) {
    ec_jacobi_addrdc(ctx->gpoints + i, ctx->gpoints + i - 1, &g1);
  }
  for (size_t i = 0; i < hsize; ++i) {
    pe_clone(&ctx->gpoints[hsize + i], &ctx->gpoints[i]);
    fe_modp_neg(ctx->gpoints[hsize + i].y, ctx->gpoints[i].y);
  }
}

void pk_verify_hash(const fe pk, const h160_t hash, bool c, size_t endo) {
  pe point;
  ec_jacobi_mulrdc(&point, &G1, pk);

  h160_t h;
  c ? addr33(h, &point) : addr65(h, &point);

  bool is_equal = memcmp(h, hash, sizeof(h160_t)) == 0;
  if (!is_equal) {
    fprintf(stderr, "[!] error: hash mismatch (compressed: %d endo: %zu)\n", c, endo);
    fprintf(stderr, "pk: %016llx%016llx%016llx%016llx\n", pk[3], pk[2], pk[1], pk[0]);
    fprintf(stderr, "lh: %08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4]);
    fprintf(stderr, "rh: %08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4]);
    exit(1);
  }
}

void calc_priv(fe pk, const fe start_pk, const fe stride_k, size_t pk_off, u8 endo) {
  fe_modn_add_stride(pk, start_pk, stride_k, pk_off);
  if (endo == 0) return;
  if (endo == 1) fe_modn_neg(pk, pk);
  if (endo == 2 || endo == 3) fe_modn_mul(pk, pk, A1);
  if (endo == 3) fe_modn_neg(pk, pk);
  if (endo == 4 || endo == 5) fe_modn_mul(pk, pk, A2);
  if (endo == 5) fe_modn_neg(pk, pk);
}

void check_hash(ctx_t *ctx, bool c, const h160_t h, const fe start_pk, u64 pk_off, size_t endo) {
  if (!ctx_check_hash(ctx, h)) return;
  fe ck;
  calc_priv(ck, start_pk, ctx->stride_k, pk_off, endo);
  pk_verify_hash(ck, h, c, endo);
  ctx_write_found(ctx, c ? "addr33" : "addr65", h, ck);
}

void check_found_add(ctx_t *ctx, fe const start_pk, const pe *points) {
  h160_t hs33[HASH_BATCH_SIZE];
  h160_t hs65[HASH_BATCH_SIZE];

  for (size_t i = 0; i < GROUP_INV_SIZE; i += HASH_BATCH_SIZE) {
    if (ctx->check_addr33) addr33_batch(hs33, points + i, HASH_BATCH_SIZE);
    if (ctx->check_addr65) addr65_batch(hs65, points + i, HASH_BATCH_SIZE);
    for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
      if (ctx->check_addr33) check_hash(ctx, true, hs33[j], start_pk, i + j, 0);
      if (ctx->check_addr65) check_hash(ctx, false, hs65[j], start_pk, i + j, 0);
    }
  }

  if (!ctx->use_endo) return;

  size_t esize = HASH_BATCH_SIZE * 5;
  pe endos[esize];
  for (size_t i = 0; i < esize; ++i) fe_set64(endos[i].z, 1);

  size_t ci = 0;
  for (size_t k = 0; k < GROUP_INV_SIZE; ++k) {
    size_t idx = (k * 5) % esize;

    fe_clone(endos[idx + 0].x, points[k].x);
    fe_modp_neg(endos[idx + 0].y, points[k].y);

    fe_modp_mul(endos[idx + 1].x, points[k].x, B1);
    fe_clone(endos[idx + 1].y, points[k].y);

    fe_clone(endos[idx + 2].x, endos[idx + 1].x);
    fe_clone(endos[idx + 2].y, endos[idx + 0].y);

    fe_modp_mul(endos[idx + 3].x, points[k].x, B2);
    fe_clone(endos[idx + 3].y, points[k].y);

    fe_clone(endos[idx + 4].x, endos[idx + 3].x);
    fe_clone(endos[idx + 4].y, endos[idx + 0].y);

    bool is_full = (idx + 5) % esize == 0 || k == GROUP_INV_SIZE - 1;
    if (!is_full) continue;

    for (size_t i = 0; i < esize; i += HASH_BATCH_SIZE) {
      if (ctx->check_addr33) addr33_batch(hs33, endos + i, HASH_BATCH_SIZE);
      if (ctx->check_addr65) addr65_batch(hs65, endos + i, HASH_BATCH_SIZE);

      for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
        if (ctx->check_addr33) check_hash(ctx, true, hs33[j], start_pk, ci / 5, (ci % 5) + 1);
        if (ctx->check_addr65) check_hash(ctx, false, hs65[j], start_pk, ci / 5, (ci % 5) + 1);
        ci += 1;
      }
    }
  }
  assert(ci == GROUP_INV_SIZE * 5);
}

void batch_add(ctx_t *ctx, const fe pk, const size_t iterations) {
  size_t hsize = GROUP_INV_SIZE / 2;

  pe bp[GROUP_INV_SIZE];
  fe dx[hsize];
  pe GStart;
  fe ck, rx, ry;
  fe ss, dd;

  fe_modn_add_stride(ss, pk, ctx->stride_k, hsize);
  ec_jacobi_mulrdc(&GStart, &G1, ss);

  fe_clone(ck, pk);

  size_t counter = 0;
  while (counter < iterations) {
    for (size_t i = 0; i < hsize; ++i) fe_modp_sub(dx[i], ctx->gpoints[i].x, GStart.x);
    fe_modp_grpinv(dx, hsize);

    pe_clone(&bp[hsize + 0], &GStart);

    for (size_t D = 0; D < 2; ++D) {
      bool positive = D == 0;
      size_t g_idx = positive ? 0 : hsize;
      size_t g_max = positive ? hsize - 1 : hsize;
      for (size_t i = 0; i < g_max; ++i) {
        fe_modp_sub(ss, ctx->gpoints[g_idx + i].y, GStart.y);
        fe_modp_mul(ss, ss, dx[i]);
        fe_modp_sqr(rx, ss);
        fe_modp_sub(rx, rx, GStart.x);
        fe_modp_sub(rx, rx, ctx->gpoints[g_idx + i].x);
        fe_modp_sub(dd, GStart.x, rx);
        fe_modp_mul(dd, ss, dd);
        fe_modp_sub(ry, dd, GStart.y);

        size_t idx = positive ? hsize + i + 1 : hsize - 1 - i;
        fe_clone(bp[idx].x, rx);
        fe_clone(bp[idx].y, ry);
        fe_set64(bp[idx].z, 0x1);
      }
    }

    check_found_add(ctx, ck, bp);
    if (__atomic_load_n(&ctx->stop_animation, __ATOMIC_RELAXED)) break;

    fe_modn_add_stride(ck, ck, ctx->stride_k, GROUP_INV_SIZE);
    ec_jacobi_addrdc(&GStart, &GStart, &ctx->stride_p);
    counter += GROUP_INV_SIZE;
  }
}

void *cmd_add_worker(void *arg) {
  ctx_t *ctx = (ctx_t *)arg;

  fe initial_r;
  fe_clone(initial_r, ctx->range_s);

  fe inc = {0};
  fe_set64(inc, ctx->job_size);
  fe_modn_mul(inc, inc, ctx->stride_k);

  fe pk;
  while (true) {
    if (__atomic_load_n(&ctx->stop_animation, __ATOMIC_RELAXED)) break;

    pthread_mutex_lock(&ctx->lock);
    bool is_overflow = fe_cmp(ctx->range_s, initial_r) < 0;
    if (fe_cmp(ctx->range_s, ctx->range_e) >= 0 || is_overflow) {
      pthread_mutex_unlock(&ctx->lock);
      break;
    }
    fe_clone(pk, ctx->range_s);
    fe_modn_add(ctx->range_s, ctx->range_s, inc);
    pthread_mutex_unlock(&ctx->lock);

    batch_add(ctx, pk, ctx->job_size);
    ctx_update(ctx, ctx->use_endo ? ctx->job_size * 6 : ctx->job_size);
  }
  return NULL;
}

void cmd_add(ctx_t *ctx) {
  ctx_precompute_gpoints(ctx);

  fe range_size;
  fe_modn_sub(range_size, ctx->range_e, ctx->range_s);
  ctx->job_size = fe_cmp64(range_size, MAX_JOB_SIZE) < 0 ? range_size[0] : MAX_JOB_SIZE;
  ctx->ts_started = tsnow();

  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_create(&ctx->threads[i], NULL, cmd_add_worker, ctx);
  }
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_join(ctx->threads[i], NULL);
  }
}

void check_found_mul(ctx_t *ctx, const fe *pk, const pe *cp, size_t cnt) {
  h160_t hs33[HASH_BATCH_SIZE];
  h160_t hs65[HASH_BATCH_SIZE];

  for (size_t i = 0; i < cnt; i += HASH_BATCH_SIZE) {
    size_t batch_size = MIN(HASH_BATCH_SIZE, cnt - i);
    if (ctx->check_addr33) addr33_batch(hs33, cp + i, batch_size);
    if (ctx->check_addr65) addr65_batch(hs65, cp + i, batch_size);

    for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
      if (ctx->check_addr33 && ctx_check_hash(ctx, hs33[j])) {
        ctx_write_found(ctx, "addr33", hs33[j], pk[i + j]);
      }
      if (ctx->check_addr65 && ctx_check_hash(ctx, hs65[j])) {
        ctx_write_found(ctx, "addr65", hs65[j], pk[i + j]);
      }
    }
  }
}

typedef struct cmd_mul_job_t {
  size_t count;
  char lines[GROUP_INV_SIZE][MAX_LINE_SIZE];
} cmd_mul_job_t;

void *cmd_mul_worker(void *arg) {
  ctx_t *ctx = (ctx_t *)arg;

  u8 msg[(MAX_LINE_SIZE + 63 + 9) / 64 * 64] = {0};
  u32 res[8] = {0};

  fe pk[GROUP_INV_SIZE];
  pe cp[GROUP_INV_SIZE];
  cmd_mul_job_t *job = NULL;

  while (true) {
    if (job != NULL) free(job);
    job = queue_get(&ctx->queue);
    if (job == NULL) break;

    if (!ctx->raw_text) {
      for (size_t i = 0; i < job->count; ++i) fe_modn_from_hex(pk[i], job->lines[i]);
    } else {
      for (size_t i = 0; i < job->count; ++i) {
        size_t len = strlen(job->lines[i]);
        size_t msg_size = (len + 63 + 9) / 64 * 64;

        size_t bitlen = len * 8;
        memcpy(msg, job->lines[i], len);
        memset(msg + len, 0, msg_size - len);
        msg[len] = 0x80;
        for (int j = 0; j < 8; j++) msg[msg_size - 1 - j] = bitlen >> (j * 8);
        sha256_final(res, (u8 *)msg, msg_size);

        pk[i][0] = (u64)res[6] << 32 | res[7];
        pk[i][1] = (u64)res[4] << 32 | res[5];
        pk[i][2] = (u64)res[2] << 32 | res[3];
        pk[i][3] = (u64)res[0] << 32 | res[1];
      }
    }

    for (size_t i = 0; i < job->count; ++i) ec_gtable_mul(&cp[i], pk[i]);
    ec_jacobi_grprdc(cp, job->count);

    check_found_mul(ctx, pk, cp, job->count);
    ctx_update(ctx, job->count);
    if (__atomic_load_n(&ctx->stop_animation, __ATOMIC_RELAXED)) break;
  }

  if (job != NULL) free(job);
  return NULL;
}

void cmd_mul(ctx_t *ctx) {
  ec_gtable_init();

  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_create(&ctx->threads[i], NULL, cmd_mul_worker, ctx);
  }

  cmd_mul_job_t *job = calloc(1, sizeof(cmd_mul_job_t));
  char line[MAX_LINE_SIZE];

  while (fgets(line, sizeof(line), stdin) != NULL) {
    if (__atomic_load_n(&ctx->stop_animation, __ATOMIC_RELAXED)) break;
    size_t len = strlen(line);
    if (len && line[len - 1] == '\n') line[--len] = '\0';
    if (len && line[len - 1] == '\r') line[--len] = '\0';
    if (len == 0) continue;

    strcpy(job->lines[job->count++], line);
    if (job->count == GROUP_INV_SIZE) {
      queue_put(&ctx->queue, job);
      job = calloc(1, sizeof(cmd_mul_job_t));
    }
  }

  if (job->count > 0 && job->count != GROUP_INV_SIZE) {
    queue_put(&ctx->queue, job);
  }

  queue_done(&ctx->queue);

  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_join(ctx->threads[i], NULL);
  }
}

void gen_random_range(ctx_t *ctx, const fe a, const fe b) {
  // true_random => pick a fresh random center and scan a big chunk
  if (ctx->true_random) {
    fe_rand_range(ctx->range_s, a, b, !ctx->has_seed);
    fe_clone(ctx->range_e, ctx->range_s);

    // Expand a window of bits around a random center, big enough for throughput
    u32 win = 32 + (rand64(false) % 33); // 32..64 bits window
    u32 ofs = rand64(false) % (256 - win);
    for (u32 i = ofs; i < (ofs + win); ++i) {
      ctx->range_s[i / 64] &= ~(1ULL << (i % 64));
      ctx->range_e[i / 64] |= 1ULL << (i % 64);
    }

    // Keep in bounds
    if (fe_cmp(ctx->range_s, a) <= 0) fe_clone(ctx->range_s, a);
    if (fe_cmp(ctx->range_e, b) >= 0) fe_clone(ctx->range_e, b);
    return;
  }

  // Original rnd behavior with offset/size mask
  fe_rand_range(ctx->range_s, a, b, !ctx->has_seed);
  fe_clone(ctx->range_e, ctx->range_s);
  for (u32 i = ctx->ord_offs; i < (ctx->ord_offs + ctx->ord_size); ++i) {
    ctx->range_s[i / 64] &= ~(1ULL << (i % 64));
    ctx->range_e[i / 64] |= 1ULL << (i % 64);
  }
  if (fe_cmp(ctx->range_s, a) <= 0) fe_clone(ctx->range_s, a);
  if (fe_cmp(ctx->range_e, b) >= 0) fe_clone(ctx->range_e, b);
}

static void print_range_mask(fe range_s, u32 bits_size, u32 offset, bool use_color) {
  // In matrix edition we won’t print these masks in normal flow.
  // Kept for compatibility; no-op unless you want to debug.
  (void)range_s; (void)bits_size; (void)offset; (void)use_color;
}

void cmd_rnd(ctx_t *ctx) {
  ctx->ord_offs = MIN(ctx->ord_offs, 255 - ctx->ord_size);

  ctx_precompute_gpoints(ctx);
  ctx->job_size = MAX_JOB_SIZE;
  ctx->ts_started = tsnow();

  fe range_s, range_e;
  fe_clone(range_s, ctx->range_s);
  fe_clone(range_e, ctx->range_e);

  while (!__atomic_load_n(&ctx->stop_animation, __ATOMIC_RELAXED)) {
    gen_random_range(ctx, range_s, range_e);

    for (size_t i = 0; i < ctx->threads_count; ++i) {
      pthread_create(&ctx->threads[i], NULL, cmd_add_worker, ctx);
    }
    for (size_t i = 0; i < ctx->threads_count; ++i) {
      pthread_join(ctx->threads[i], NULL);
    }

    if (ctx->key_found_flag) break;
    // if not true_random and we used the full range once, break (original behavior)
    if (!ctx->true_random &&
        fe_cmp(ctx->range_s, range_s) == 0 && fe_cmp(ctx->range_e, range_e) == 0) break;
  }
}

// ---------- Args helpers (add -d 0:0 true random) ----------

void arg_search_range(args_t *args, fe range_s, fe range_e) {
  char *raw = arg_str(args, "-r");
  if (!raw) {
    fe_set64(range_s, GROUP_INV_SIZE);
    fe_clone(range_e, FE_P);
    return;
  }

  char *sep = strchr(raw, ':');
  if (!sep) {
    fprintf(stderr, "invalid search range, use format: -r 8000:ffff\n");
    exit(1);
  }

  *sep = 0;
  fe_modn_from_hex(range_s, raw);
  fe_modn_from_hex(range_e, sep + 1);

  if (fe_cmp64(range_s, GROUP_INV_SIZE) <= 0) {
    fprintf(stderr, "invalid search range, start <= %#lx\n", GROUP_INV_SIZE);
    exit(1);
  }
  if (fe_cmp(range_e, FE_P) > 0) {
    fprintf(stderr, "invalid search range, end > FE_P\n");
    exit(1);
  }
  if (fe_cmp(range_s, range_e) >= 0) {
    fprintf(stderr, "invalid search range, start >= end\n");
    exit(1);
  }
}

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
    ctx->true_random = false;
    return;
  }
  if (!raw) {
    ctx->ord_offs = 0;
    ctx->ord_size = default_bits;
    ctx->true_random = false;
    return;
  }

  char *sep = strchr(raw, ':');
  if (!sep) {
    fprintf(stderr, "invalid offset:size format, use format: -d 128:32\n");
    exit(1);
  }

  *sep = 0;
  u32 tmp_offs = atoi(raw);
  u32 tmp_size = atoi(sep + 1);

  // Handle -d 0:0 => true random mode
  if (tmp_offs == 0 && tmp_size == 0) {
    ctx->ord_offs = 0;
    ctx->ord_size = 0;
    ctx->true_random = true;
    return;
  }

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
  ctx->true_random = false;
}

// ---------- MATRIX UI RENDERER ----------

typedef struct col_state_t {
  int head_row;     // current head position
  int speed_ms;     // per-step delay
  int tick_ms;      // accumulated time
  int trail_len;    // length of fade trail
} col_state_t;

static inline int clampi(int v, int a, int b) { return v < a ? a : (v > b ? b : v); }

static void get_term_size(int *rows, int *cols) {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0) {
    *rows = ws.ws_row;
    *cols = ws.ws_col;
  } else {
    *rows = 24; *cols = 80;
  }
}

static inline char hexrand() {
  const char *H = "0123456789ABCDEF";
  return H[rand64(false) & 0xF];
}

static void draw_stats(ctx_t *ctx) {
  pthread_mutex_lock(&ctx->lock);
  double spd = ctx->speed_mkeys;
  size_t tot = ctx->k_checked;
  size_t th = ctx->threads_count;
  pthread_mutex_unlock(&ctx->lock);

  ansi_move(1,1); ansi_clear_line();
  set_fg256(118);
  printf("SPEED: %.2f Mkeys/s | TOTAL SCANNED: %'zu | THREADS: %'zu", spd, tot, th);
  fputs(RESET_COLORS, stdout);
}

static void *matrix_thread(void *arg) {
  ctx_t *ctx = (ctx_t *)arg;
  ctx->ui_running = true;

  // Initial terminal prep
  fputs(HIDE_CURSOR, stdout);
  fputs(CLEAR_SCREEN, stdout);
  fflush(stdout);

  // Get size; reserve first row for stats
  get_term_size(&ctx->term_rows, &ctx->term_cols);
  int rows = ctx->term_rows;
  int cols = ctx->term_cols;
  int top_row = 2; // stats at row 1, rain starts at row 2
  int rain_rows = MAX(1, rows - (top_row - 1));

  // Initialize columns
  col_state_t *col = (col_state_t*)calloc(cols, sizeof(col_state_t));
  for (int x = 0; x < cols; ++x) {
    col[x].head_row = rand64(false) % rain_rows;
    col[x].speed_ms = 20 + (rand64(false) % 80); // 20..99ms per tick
    col[x].tick_ms  = 0;
    col[x].trail_len = 6 + (rand64(false) % 14); // 6..19 length
  }

  // For smoother timing
  const int frame_ms = 30; // ~33 FPS
  size_t last_ts = tsnow();

  while (!__atomic_load_n(&ctx->stop_animation, __ATOMIC_RELAXED)) {
    // Resize check
    int r,c;
    get_term_size(&r, &c);
    if (r != rows || c != cols) {
      rows = r; cols = c; ctx->term_rows = r; ctx->term_cols = c;
      rain_rows = MAX(1, rows - (top_row - 1));
      col = (col_state_t*)realloc(col, cols * sizeof(col_state_t));
      for (int x = 0; x < cols; ++x) {
        if (col[x].trail_len == 0) {
          col[x].head_row = rand64(false) % rain_rows;
          col[x].speed_ms = 20 + (rand64(false) % 80);
          col[x].trail_len = 6 + (rand64(false) % 14);
        } else {
          col[x].head_row %= rain_rows;
        }
      }
      fputs(CLEAR_SCREEN, stdout);
    }

    // Draw stats on top
    draw_stats(ctx);

    // Draw rain (column-wise updates)
    for (int x = 1; x <= cols; ++x) {
      // advance tick
      col[x-1].tick_ms += frame_ms;
      if (col[x-1].tick_ms < col[x-1].speed_ms) continue;
      col[x-1].tick_ms = 0;

      // Erase character above trail (to avoid flicker, only when needed)
      int erase_row = top_row + col[x-1].head_row - col[x-1].trail_len;
      if (erase_row >= top_row && erase_row <= rows) {
        ansi_move(erase_row, x);
        putchar(' ');
      }

      // Draw trail with fading shades
      for (int t = col[x-1].trail_len - 1; t >= 0; --t) {
        int rr = top_row + col[x-1].head_row - t;
        if (rr < top_row || rr > rows) continue;
        int shade_idx = clampi(GREEN_LEVELS - 1 - (t * GREEN_LEVELS / col[x-1].trail_len), 0, GREEN_LEVELS - 1);
        set_fg256(GREEN_SHADE[shade_idx]);
        ansi_move(rr, x);
        putchar(hexrand());
      }
      // Advance head
      col[x-1].head_row = (col[x-1].head_row + 1) % rain_rows;
    }

    fputs(RESET_COLORS, stdout);
    fflush(stdout);

    // pacing
    size_t now = tsnow();
    size_t elapsed = now - last_ts;
    if (elapsed < (size_t)frame_ms) usleep((frame_ms - elapsed) * 1000);
    last_ts = tsnow();
  }

  // Final screen: clear & show found message (if any)
  fputs(RESET_COLORS, stdout);
  fputs(CLEAR_SCREEN, stdout);
  ansi_move(1,1);
  if (ctx->key_found_flag) {
    // print single final line
    char pkhex[65] = {0};
    fe_print_hex_to(pkhex, sizeof(pkhex), ctx->found_pk);
    set_fg256(118);
    printf("KEY FOUND: %s\n", pkhex);
  }
  fputs(SHOW_CURSOR, stdout);
  fflush(stdout);

  free(col);
  ctx->ui_running = false;
  return NULL;
}

// ---------- TTY pause/resume (kept for functionality) ----------

void handle_sigint(int sig) {
  fflush(stderr);
  fflush(stdout);
  printf("\n");
  exit(sig);
}

void tty_cb(void *ctx_raw, const char ch) {
  ctx_t *ctx = (ctx_t *)ctx_raw;
  if (ch == 'p' && !ctx->paused) {
    ctx->ts_paused_at = tsnow();
    ctx->paused = true;
  }
  if (ch == 'r' && ctx->paused) {
    ctx->paused_time += tsnow() - ctx->ts_paused_at;
    ctx->paused = false;
  }
}

// ---------- Main / init (prints minimized, starts UI thread) ----------

void usage(const char *name) {
  printf("Usage: %s <cmd> [-t <threads>] [-f <file>] [-a <addr_type>] [-r <range>]\n", name);
  printf("v%s ~ https://github.com/vladkens/ecloop\n", VERSION);
  printf("\nCompute commands:\n");
  printf("  add             - search in given range with batch addition\n");
  printf("  mul             - search hex encoded private keys (from stdin)\n");
  printf("  rnd             - search random range of bits in given range (or -d 0:0 true random)\n");
  printf("\nCompute options:\n");
  printf("  -f <file>       - filter file to search (list of hashes or bloom filter)\n");
  printf("  -o <file>       - output file to write found keys (default: none)\n");
  printf("  -t <threads>    - number of threads to run (default: #cpus)\n");
  printf("  -a <addr_type>  - address type to search: c - addr33, u - addr65 (default: c)\n");
  printf("  -r <range>      - search range in hex format (example: 8000:ffff, default all)\n");
  printf("  -d <offs:size>  - bit offset and size for search (example: 128:32; use 0:0 for true random)\n");
  printf("  -q              - quiet mode (no stdout UI; requires -o to save hits)\n");
  printf("  -endo           - use endomorphism (default: false; ignored for mul)\n");
  printf("\nOther commands:\n");
  printf("  blf-gen         - create bloom filter from list of hex-encoded hash160\n");
  printf("  blf-check       - check bloom filter for given hex-encoded hash160\n");
  printf("  bench           - run benchmark of internal functions\n");
  printf("  bench-gtable    - run benchmark of ecc multiplication (with different table size)\n");
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

  ctx->cmd = CMD_NIL;
  if (args->argc > 1) {
    if (strcmp(args->argv[1], "add") == 0) ctx->cmd = CMD_ADD;
    if (strcmp(args->argv[1], "mul") == 0) ctx->cmd = CMD_MUL;
    if (strcmp(args->argv[1], "rnd") == 0) ctx->cmd = CMD_RND;
  }

  if (ctx->cmd == CMD_NIL) {
    if (args_bool(args, "-v")) printf("ecloop v%s\n", VERSION);
    else usage(args->argv[0]);
    exit(0);
  }

  ctx->has_seed = false;
  char *seed = arg_str(args, "-seed");
  if (seed != NULL) {
    ctx->has_seed = true;
    srand(encode_seed(seed));
    free(seed);
  }

  char *path = arg_str(args, "-f");
  load_filter(ctx, path);

  ctx->quiet = args_bool(args, "-q");
  char *outfile = arg_str(args, "-o");
  if (outfile) ctx->outfile = fopen(outfile, "a");
  if (outfile == NULL && ctx->quiet) {
    fprintf(stderr, "quiet mode chosen without output file\n");
    exit(1);
  }

  char *addr = arg_str(args, "-a");
  ctx->check_addr33 = true;
  ctx->check_addr65 = false;
  if (addr) {
    ctx->check_addr33 = strstr(addr, "c") != NULL;
    ctx->check_addr65 = strstr(addr, "u") != NULL;
    if (!ctx->check_addr33 && !ctx->check_addr65) ctx->check_addr33 = true;
  }

  ctx->use_endo = args_bool(args, "-endo");
  if (ctx->cmd == CMD_MUL) ctx->use_endo = false;

  pthread_mutex_init(&ctx->lock, NULL);
  int cpus = get_cpu_count();
  ctx->threads_count = MIN(MAX(args_uint(args, "-t", cpus), 1ul), 320ul);
  ctx->threads = malloc(ctx->threads_count * sizeof(pthread_t));
  ctx->finished = false;
  ctx->k_checked = 0;
  ctx->k_found = 0;
  ctx->ts_started = tsnow();
  ctx->ts_updated = ctx->ts_started;
  ctx->ts_printed = ctx->ts_started - 5e3;
  ctx->paused_time = 0;
  ctx->paused = false;

  arg_search_range(args, ctx->range_s, ctx->range_e);
  load_offs_size(ctx, args);
  queue_init(&ctx->queue, ctx->threads_count * 3);

  // Kick off UI unless in quiet
  if (!ctx->quiet) {
    ctx->stop_animation = false;
    ctx->key_found_flag = false;
    pthread_create(&ctx->ui_thread, NULL, matrix_thread, ctx);
  }
}

int main(int argc, const char **argv) {
  setlocale(LC_NUMERIC, "");
  args_t args = {argc, argv};
  ctx_t ctx = {0};
  init(&ctx, &args);

  signal(SIGINT, handle_sigint);
  tty_init(tty_cb, &ctx);

  if (ctx.cmd == CMD_ADD) cmd_add(&ctx);
  if (ctx.cmd == CMD_MUL) cmd_mul(&ctx);
  if (ctx.cmd == CMD_RND) cmd_rnd(&ctx);

  ctx_finish(&ctx);

  // If quiet mode, print key found here (no UI thread)
  if (ctx.quiet && ctx.key_found_flag) {
    char pkhex[65] = {0};
    fe_print_hex_to(pkhex, sizeof(pkhex), ctx.found_pk);
    printf("KEY FOUND: %s\n", pkhex);
  }

  return 0;
}
