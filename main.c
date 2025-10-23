// Copyright (c) vladkens
// https://github.com/vladkens/ecloop
// Licensed under the MIT License.

#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>

#include "lib/addr.c"
#include "lib/bench.c"
#include "lib/ecc.c"
#include "lib/utils.c"

#define VERSION "0.5.2-matrix"
#define MAX_JOB_SIZE 1024 * 1024 * 2
#define GROUP_INV_SIZE 2048ul
#define MAX_LINE_SIZE 1025
#define MATRIX_COLS 80
#define MATRIX_ROWS 24

static_assert(GROUP_INV_SIZE % HASH_BATCH_SIZE == 0,
              "GROUP_INV_SIZE must be divisible by HASH_BATCH_SIZE");

enum Cmd { CMD_NIL, CMD_ADD, CMD_MUL, CMD_RND };

typedef struct ctx_t {
  enum Cmd cmd;
  pthread_mutex_t lock;
  size_t threads_count;
  pthread_t *threads;
  _Atomic size_t k_checked;
  _Atomic size_t k_found;
  bool check_addr33;
  bool check_addr65;
  bool use_endo;

  FILE *outfile;
  bool quiet;
  bool use_color;

  _Atomic bool finished;
  bool paused;
  size_t ts_started;
  size_t ts_updated;
  size_t ts_printed;
  size_t ts_paused_at;
  size_t paused_time;

  h160_t *to_find_hashes;
  size_t to_find_count;
  blf_t blf;

  fe range_s;
  fe range_e;
  fe stride_k;
  pe stride_p;
  pe gpoints[GROUP_INV_SIZE];
  size_t job_size;

  queue_t queue;
  bool raw_text;

  bool has_seed;
  u32 ord_offs;
  u32 ord_size;
  
  // Matrix display
  bool pure_random_mode;
  char matrix_keys[10][65];
  int matrix_index;
  char current_key[65];
  
  // Matrix rain effect
  char matrix_rain[MATRIX_ROWS][MATRIX_COLS];
  int rain_positions[MATRIX_COLS];
  int rain_speeds[MATRIX_COLS];
} ctx_t;

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

  size_t unique_count = 0;
  for (size_t i = 1; i < size; ++i) {
    if (memcmp(&hashes[unique_count * 5], &hashes[i * 5], hlen) != 0) {
      unique_count++;
      memcpy(&hashes[unique_count * 5], &hashes[i * 5], hlen);
    }
  }

  ctx->to_find_hashes = (h160_t *)hashes;
  ctx->to_find_count = unique_count + 1;

  ctx->blf.size = ctx->to_find_count * 2;
  ctx->blf.bits = malloc(ctx->blf.size * sizeof(u64));
  for (size_t i = 0; i < ctx->to_find_count; ++i) blf_add(&ctx->blf, hashes + i * 5);
}

// Initialize Matrix rain effect
void init_matrix_rain(ctx_t *ctx) {
  for (int col = 0; col < MATRIX_COLS; col++) {
    ctx->rain_positions[col] = rand() % MATRIX_ROWS;
    ctx->rain_speeds[col] = 1 + (rand() % 3);
  }
  
  for (int row = 0; row < MATRIX_ROWS; row++) {
    for (int col = 0; col < MATRIX_COLS; col++) {
      ctx->matrix_rain[row][col] = "0123456789ABCDEF"[rand() % 16];
    }
  }
}

// Update Matrix rain animation
void update_matrix_rain(ctx_t *ctx, const fe pk) {
  static int frame_counter = 0;
  frame_counter++;
  
  // Update rain columns
  for (int col = 0; col < MATRIX_COLS; col++) {
    if (frame_counter % ctx->rain_speeds[col] == 0) {
      // Scroll column down
      for (int row = MATRIX_ROWS - 1; row > 0; row--) {
        ctx->matrix_rain[row][col] = ctx->matrix_rain[row - 1][col];
      }
      
      // Add new character at top (from current scanning key if available)
      if (strlen(ctx->current_key) > 0 && col < 64) {
        ctx->matrix_rain[0][col] = ctx->current_key[col];
      } else {
        ctx->matrix_rain[0][col] = "0123456789ABCDEF"[rand() % 16];
      }
    }
  }
  
  // Update current key
  pthread_mutex_lock(&ctx->lock);
  snprintf(ctx->current_key, 65, "%016llx%016llx%016llx%016llx", 
           pk[3], pk[2], pk[1], pk[0]);
  pthread_mutex_unlock(&ctx->lock);
}

// Draw Matrix-style display with falling rain
void draw_matrix_display(ctx_t *ctx) {
  int64_t effective_time = (int64_t)(ctx->ts_updated - ctx->ts_started) - (int64_t)ctx->paused_time;
  double dt = MAX(1, effective_time) / 1000.0;
  double speed = atomic_load(&ctx->k_checked) / dt / 1000000;
  
  // Clear screen and move cursor to top
  printf("\033[2J\033[H");
  
  // Draw Matrix rain
  for (int row = 0; row < MATRIX_ROWS - 3; row++) {
    for (int col = 0; col < MATRIX_COLS; col++) {
      // Calculate color intensity based on position
      int intensity;
      if (row == 0) {
        intensity = 46; // Brightest green
      } else if (row < 5) {
        intensity = 46 - (row * 2);
      } else if (row < 10) {
        intensity = 36 - ((row - 5) * 2);
      } else {
        intensity = 22; // Dimmest
      }
      
      printf("\033[38;5;%dm%c\033[0m", intensity, ctx->matrix_rain[row][col]);
    }
    printf("\n");
  }
  
  // Stats at bottom (clean, minimal)
  printf("\n");
  printf("\033[1;32mSPEED:\033[0m %.2f MKeys/s  ", speed);
  printf("\033[1;33mTOTAL SCANNED:\033[0m %'20zu  ", atomic_load(&ctx->k_checked));
  printf("\033[1;36mTHREADS:\033[0m %zu\n", ctx->threads_count);
  
  fflush(stdout);
}

void update_matrix_keys(ctx_t *ctx, const fe pk) {
  update_matrix_rain(ctx, pk);
}

void ctx_print_unlocked(ctx_t *ctx) {
  if (ctx->pure_random_mode) {
    draw_matrix_display(ctx);
    return;
  }
  
  char *msg = atomic_load(&ctx->finished) ? "" : (ctx->paused ? " ('r' – resume)" : " ('p' – pause)");

  int64_t effective_time = (int64_t)(ctx->ts_updated - ctx->ts_started) - (int64_t)ctx->paused_time;
  double dt = MAX(1, effective_time) / 1000.0;
  double it = atomic_load(&ctx->k_checked) / dt / 1000000;
  term_clear_line();
  fprintf(stderr, "%.2fs ~ %.2f Mkeys/s ~ %'zu / %'zu%s%c",
          dt, it, atomic_load(&ctx->k_found), atomic_load(&ctx->k_checked), msg, atomic_load(&ctx->finished) ? '\n' : '\r');
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
  bool need_print = (ts - ctx->ts_printed) >= 50; // 50ms for smooth animation
  atomic_fetch_add(&ctx->k_checked, k_checked);
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
  atomic_store(&ctx->finished, true);
  
  if (ctx->pure_random_mode) {
    printf("\033[2J\033[H");
    
    if (atomic_load(&ctx->k_found) > 0) {
      printf("\n\n");
      printf("\033[1;32m╔════════════════════════════════════════════════════════════════════╗\033[0m\n");
      printf("\033[1;32m║                         KEY FOUND!                                 ║\033[0m\n");
      printf("\033[1;32m╚════════════════════════════════════════════════════════════════════╝\033[0m\n");
      printf("\n");
      
      if (strlen(ctx->current_key) > 0) {
        printf("\033[1;37mKEY:\033[0m \033[1;33m0x%s\033[0m\n\n", ctx->current_key);
      }
      
      int64_t effective_time = (int64_t)(ctx->ts_updated - ctx->ts_started) - (int64_t)ctx->paused_time;
      double dt = MAX(1, effective_time) / 1000.0;
      double speed = atomic_load(&ctx->k_checked) / dt / 1000000;
      
      printf("Time elapsed: \033[1;36m%.2f\033[0m seconds\n", dt);
      printf("Total scanned: \033[1;36m%'zu\033[0m keys\n", atomic_load(&ctx->k_checked));
      printf("Average speed: \033[1;36m%.2f\033[0m MKeys/s\n", speed);
    }
  } else {
    ctx_print_unlocked(ctx);
  }
  
  if (ctx->outfile != NULL) fclose(ctx->outfile);
  pthread_mutex_unlock(&ctx->lock);
}

void ctx_write_found(ctx_t *ctx, const char *label, const h160_t hash, const fe pk) {
  pthread_mutex_lock(&ctx->lock);

  if (!ctx->quiet) {
    if (ctx->pure_random_mode) {
      snprintf(ctx->current_key, 65, "%016llx%016llx%016llx%016llx", 
               pk[3], pk[2], pk[1], pk[0]);
    } else {
      term_clear_line();
      printf("%s: %08x%08x%08x%08x%08x <- %016llx%016llx%016llx%016llx\n",
             label, hash[0], hash[1], hash[2], hash[3], hash[4],
             pk[3], pk[2], pk[1], pk[0]);
    }
  }

  if (ctx->outfile != NULL) {
    fprintf(ctx->outfile, "%s\t%08x%08x%08x%08x%08x\t%016llx%016llx%016llx%016llx\n",
            label, hash[0], hash[1], hash[2], hash[3], hash[4],
            pk[3], pk[2], pk[1], pk[0]);
    fflush(ctx->outfile);
  }

  atomic_fetch_add(&ctx->k_found, 1);
  atomic_store(&ctx->finished, true);
  
  if (!ctx->pure_random_mode) {
    ctx_print_unlocked(ctx);
  }

  pthread_mutex_unlock(&ctx->lock);
}

bool ctx_check_hash(ctx_t *ctx, const h160_t h) {
  if (ctx->to_find_hashes == NULL) {
    return blf_has(&ctx->blf, h);
  }

  if (!blf_has(&ctx->blf, h)) return false;

  h160_t *rs = bsearch(h, ctx->to_find_hashes, ctx->to_find_count, sizeof(h160_t), compare_160);
  return rs != NULL;
}

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

// MARK: CMD_ADD

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
    if (atomic_load(&ctx->finished)) return;
    
    if (ctx->check_addr33) addr33_batch(hs33, points + i, HASH_BATCH_SIZE);
    if (ctx->check_addr65) addr65_batch(hs65, points + i, HASH_BATCH_SIZE);
    for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
      if (ctx->check_addr33) check_hash(ctx, true, hs33[j], start_pk, i + j, 0);
      if (ctx->check_addr65) check_hash(ctx, false, hs65[j], start_pk, i + j, 0);
      
      if (atomic_load(&ctx->finished)) return;
    }
  }

  if (!ctx->use_endo) return;

  size_t esize = HASH_BATCH_SIZE * 5;
  pe endos[esize];
  for (size_t i = 0; i < esize; ++i) fe_set64(endos[i].z, 1);

  size_t ci = 0;
  for (size_t k = 0; k < GROUP_INV_SIZE; ++k) {
    if (atomic_load(&ctx->finished)) return;
    
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
      if (atomic_load(&ctx->finished)) return;
      
      if (ctx->check_addr33) addr33_batch(hs33, endos + i, HASH_BATCH_SIZE);
      if (ctx->check_addr65) addr65_batch(hs65, endos + i, HASH_BATCH_SIZE);

      for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
        if (ctx->check_addr33) check_hash(ctx, true, hs33[j], start_pk, ci / 5, (ci % 5) + 1);
        if (ctx->check_addr65) check_hash(ctx, false, hs65[j], start_pk, ci / 5, (ci % 5) + 1);
        ci += 1;
        
        if (atomic_load(&ctx->finished)) return;
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
    if (atomic_load(&ctx->finished)) return;
    
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
    
    if (ctx->pure_random_mode) {
      update_matrix_keys(ctx, ck);
    }
    
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
  while (!atomic_load(&ctx->finished)) {
    pthread_mutex_lock(&ctx->lock);
    bool is_overflow = fe_cmp(ctx->range_s, initial_r) < 0;
    if (fe_cmp(ctx->range_s, ctx->range_e) >= 0 || is_overflow || atomic_load(&ctx->finished)) {
      pthread_mutex_unlock(&ctx->lock);
      break;
    }

    fe_clone(pk, ctx->range_s);
    fe_modn_add(ctx->range_s, ctx->range_s, inc);
    pthread_mutex_unlock(&ctx->lock);

    batch_add(ctx, pk, ctx->job_size);
    ctx_update(ctx, ctx->use_endo ? ctx->job_size * 6 : ctx->job_size);
    
    if (atomic_load(&ctx->finished)) break;
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

  ctx_finish(ctx);
}

// MARK: CMD_MUL

void check_found_mul(ctx_t *ctx, const fe *pk, const pe *cp, size_t cnt) {
  h160_t hs33[HASH_BATCH_SIZE];
  h160_t hs65[HASH_BATCH_SIZE];

  for (size_t i = 0; i < cnt; i += HASH_BATCH_SIZE) {
    if (atomic_load(&ctx->finished)) return;
    
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
      
      if (atomic_load(&ctx->finished)) return;
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

  while (!atomic_load(&ctx->finished)) {
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

  while (fgets(line, sizeof(line), stdin) != NULL && !atomic_load(&ctx->finished)) {
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

  ctx_finish(ctx);
}

// MARK: CMD_RND

void gen_random_range(ctx_t *ctx, const fe a, const fe b) {
  fe_rand_range(ctx->range_s, a, b, !ctx->has_seed);
  fe_clone(ctx->range_e, ctx->range_s);
  
  if (ctx->ord_size == 0) {
    fe chunk_size;
    fe_set64(chunk_size, ctx->threads_count * ctx->job_size);
    fe_modn_add(ctx->range_e, ctx->range_s, chunk_size);
    
    if (fe_cmp(ctx->range_e, b) > 0) {
      fe_clone(ctx->range_e, b);
    }
    return;
  }
  
  for (u32 i = ctx->ord_offs; i < (ctx->ord_offs + ctx->ord_size); ++i) {
    ctx->range_s[i / 64] &= ~(1ULL << (i % 64));
    ctx->range_e[i / 64] |= 1ULL << (i % 64);
  }

  if (fe_cmp(ctx->range_s, a) <= 0) fe_clone(ctx->range_s, a);
  if (fe_cmp(ctx->range_e, b) >= 0) fe_clone(ctx->range_e, b);
}

void print_range_mask(fe range_s, u32 bits_size, u32 offset, bool use_color) {
  int mask_e = 255 - offset;
  int mask_s = mask_e - bits_size + 1;

  for (int i = 0; i < 64; i++) {
    if (i % 16 == 0 && i != 0) putchar(' ');

    int bits_s = i * 4;
    int bits_e = bits_s + 3;

    u32 fcc = (range_s[(255 - bits_e) / 64] >> ((255 - bits_e) % 64)) & 0xF;
    char cc = "0123456789abcdef"[fcc];

    bool flag = (bits_s >= mask_s && bits_s <= mask_e) || (bits_e >= mask_s && bits_e <= mask_e);
    if (flag) {
      if (use_color) fputs(COLOR_YELLOW, stdout);
      putchar(cc);
      if (use_color) fputs(COLOR_RESET, stdout);
    } else {
      putchar(cc);
    }
  }

  putchar('\n');
}

void cmd_rnd(ctx_t *ctx) {
  ctx->ord_offs = MIN(ctx->ord_offs, 255 - ctx->ord_size);
  
  if (ctx->pure_random_mode) {
    printf("\033[1;32m[MATRIX SCANNER INITIALIZED]\033[0m\n");
    printf("Threads: %zu | Address: %s\n\n", 
           ctx->threads_count, 
           ctx->check_addr33 ? "compressed" : "uncompressed");
    sleep(1);
  } else {
    printf("[RANDOM MODE] offs: %d ~ bits: %d\n\n", ctx->ord_offs, ctx->ord_size);
  }

  ctx_precompute_gpoints(ctx);
  ctx->job_size = MAX_JOB_SIZE;
  ctx->ts_started = tsnow();

  fe range_s, range_e;
  fe_clone(range_s, ctx->range_s);
  fe_clone(range_e, ctx->range_e);

  size_t last_c = 0, last_f = 0, s_time = 0;
  while (!atomic_load(&ctx->finished)) {
    last_c = atomic_load(&ctx->k_checked);
    last_f = atomic_load(&ctx->k_found);
    s_time = tsnow();

    gen_random_range(ctx, range_s, range_e);
    
    if (!ctx->pure_random_mode) {
      print_range_mask(ctx->range_s, ctx->ord_size, ctx->ord_offs, ctx->use_color);
      print_range_mask(ctx->range_e, ctx->ord_size, ctx->ord_offs, ctx->use_color);
    }
    
    ctx_print_status(ctx);

    bool is_full = fe_cmp(ctx->range_s, range_s) == 0 && fe_cmp(ctx->range_e, range_e) == 0;

    for (size_t i = 0; i < ctx->threads_count; ++i) {
      pthread_create(&ctx->threads[i], NULL, cmd_add_worker, ctx);
    }

    for (size_t i = 0; i < ctx->threads_count; ++i) {
      pthread_join(ctx->threads[i], NULL);
    }

    if (atomic_load(&ctx->finished)) break;

    if (!ctx->pure_random_mode) {
      size_t dc = atomic_load(&ctx->k_checked) - last_c;
      size_t df = atomic_load(&ctx->k_found) - last_f;
      double dt = MAX((tsnow() - s_time), 1ul) / 1000.0;
      term_clear_line();
      printf("%'zu / %'zu ~ %.1fs\n\n", df, dc, dt);
    }

    if (is_full) break;
  }

  ctx_finish(ctx);
}

// MARK: args helpers

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
    return;
  }

  if (!raw) {
    ctx->ord_offs = 0;
    ctx->ord_size = default_bits;
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

  if (tmp_offs > 255) {
    fprintf(stderr, "invalid offset, max is 255\n");
    exit(1);
  }

  if (tmp_size == 0 && tmp_offs == 0) {
    ctx->ord_offs = 0;
    ctx->ord_size = 0;
    ctx->pure_random_mode = true;
    return;
  }

  if (tmp_size < MIN_SIZE || tmp_size > MAX_SIZE) {
    fprintf(stderr, "invalid size, min is %d and max is %d (or use -d 0:0 for pure random mode)\n", MIN_SIZE, MAX_SIZE);
    exit(1);
  }

  ctx->ord_offs = MIN(max_offs, tmp_offs);
  ctx->ord_size = tmp_size;
}

// MARK: main

void usage(const char *name) {
  printf("Usage: %s <cmd> [-t <threads>] [-f <file>] [-a <addr_type>] [-r <range>]\n", name);
  printf("v%s ~ https://github.com/vladkens/ecloop\n", VERSION);
  printf("\nCompute commands:\n");
  printf("  add             - search in given range with batch addition\n");
  printf("  mul             - search hex encoded private keys (from stdin)\n");
  printf("  rnd             - search random range of bits in given range\n");
  printf("\nCompute options:\n");
  printf("  -f <file>       - filter file to search (list of hashes or bloom fitler)\n");
  printf("  -o <file>       - output file to write found keys (default: stdout)\n");
  printf("  -t <threads>    - number of threads to run (default: 1)\n");
  printf("  -a <addr_type>  - address type to search: c - addr33, u - addr65 (default: c)\n");
  printf("  -r <range>      - search range in hex format (example: 8000:ffff, default all)\n");
  printf("  -d <offs:size>  - bit offset and size for search (example: 128:32, default: 0:32)\n");
  printf("                    use -d 0:0 for MATRIX MODE with falling rain animation\n");
  printf("  -q              - quiet mode (no output to stdout; -o required)\n");
  printf("  -endo           - use endomorphism (default: false)\n");
  printf("\nOther commands:\n");
  printf("  blf-gen         - create bloom filter from list of hex-encoded hash160\n");
  printf("  blf-check       - check bloom filter for given hex-encoded hash160\n");
  printf("  bench           - run benchmark of internal functions\n");
  printf("  bench-gtable    - run benchmark of ecc multiplication (with different table size)\n");
  printf("\n");
}

void init(ctx_t *ctx, args_t *args) {
  if (args->argc > 1) {
    if (strcmp(args->argv[1], "blf-gen") == 0) return blf_gen(args);
    if (strcmp(args->argv[1], "blf-check") == 0) return blf_check(args);
    if (strcmp(args->argv[1], "bench") == 0) return run_bench();
    if (strcmp(args->argv[1], "bench-gtable") == 0) return run_bench_gtable();
    if (strcmp(args->argv[1], "mult-verify") == 0) return mult_verify();
  }

  ctx->use_color = isatty(fileno(stdout));

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
  if (addr) {
    ctx->check_addr33 = strstr(addr, "c") != NULL;
    ctx->check_addr65 = strstr(addr, "u") != NULL;
  }

  if (!ctx->check_addr33 && !ctx->check_addr65) {
    ctx->check_addr33 = true;
  }

  ctx->use_endo = args_bool(args, "-endo");
  if (ctx->cmd == CMD_MUL) ctx->use_endo = false;

  pthread_mutex_init(&ctx->lock, NULL);
  int cpus = get_cpu_count();
  ctx->threads_count = MIN(MAX(args_uint(args, "-t", cpus), 1ul), 320ul);
  ctx->threads = malloc(ctx->threads_count * sizeof(pthread_t));
  atomic_store(&ctx->finished, false);
  atomic_store(&ctx->k_checked, 0);
  atomic_store(&ctx->k_found, 0);
  ctx->ts_started = tsnow();
  ctx->ts_updated = ctx->ts_started;
  ctx->ts_printed = ctx->ts_started - 5e3;
  ctx->paused_time = 0;
  ctx->paused = false;

  ctx->pure_random_mode = false;
  ctx->matrix_index = 0;
  ctx->current_key[0] = '\0';
  for (int i = 0; i < 10; i++) {
    ctx->matrix_keys[i][0] = '\0';
  }

  arg_search_range(args, ctx->range_s, ctx->range_e);
  load_offs_size(ctx, args);
  queue_init(&ctx->queue, ctx->threads_count * 3);
  
  // Initialize Matrix rain effect
  if (ctx->pure_random_mode) {
    init_matrix_rain(ctx);
  }

  if (!ctx->pure_random_mode) {
    printf("threads: %zu ~ addr33: %d ~ addr65: %d ~ endo: %d | filter: ",
           ctx->threads_count, ctx->check_addr33, ctx->check_addr65, ctx->use_endo);

    if (ctx->to_find_hashes != NULL) printf("list (%'zu)\n", ctx->to_find_count);
    else printf("bloom\n");

    if (ctx->cmd == CMD_ADD) {
      fe_print("range_s", ctx->range_s);
      fe_print("range_e", ctx->range_e);
    }

    printf("----------------------------------------\n");
  }

  if (ctx->cmd == CMD_MUL) {
    ctx->raw_text = args_bool(args, "-raw");
  }
}

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
    ctx_print_status(ctx);
  }

  if (ch == 'r' && ctx->paused) {
    ctx->paused_time += tsnow() - ctx->ts_paused_at;
    ctx->paused = false;
    ctx_print_status(ctx);
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

  return 0;
}
