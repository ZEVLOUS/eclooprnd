// Copyright (c) vladkens
// https://github.com/vladkens/ecloop
// Licensed under the MIT License.

#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

// Include your header files instead of .c files
#include "lib/addr.h"
#include "lib/bench.h"
#include "lib/ecc.h"
#include "lib/utils.h"

#define VERSION "0.5.1"
#define MAX_JOB_SIZE (1024 * 1024 * 2)
#define GROUP_INV_SIZE 2048ul
#define MAX_LINE_SIZE 1025
#define MATRIX_KEY_SIZE 65
#define TARGET_ADDR_SIZE 64

static_assert(GROUP_INV_SIZE % HASH_BATCH_SIZE == 0,
              "GROUP_INV_SIZE must be divisible by HASH_BATCH_SIZE");

enum Cmd { CMD_NIL, CMD_ADD, CMD_MUL, CMD_RND, CMD_SCAN };

typedef struct ctx_t {
  enum Cmd cmd;
  pthread_mutex_t lock;
  pthread_cond_t pause_cond;
  size_t threads_count;
  pthread_t *threads;
  int tid;
  _Atomic bool pure_random_view;
  char sample_key[67];
  _Atomic size_t k_checked;
  _Atomic size_t k_found;
  bool check_addr33;
  bool check_addr65;
  bool use_endo;

  FILE *outfile;
  bool quiet;
  bool use_color;

  _Atomic bool finished;
  _Atomic bool paused;
  size_t ts_started;
  size_t ts_updated;
  size_t ts_printed;
  size_t ts_paused_at;
  size_t paused_time;

  // filter file (bloom filter or hashes to search)
  h160_t *to_find_hashes;
  size_t to_find_count;
  blf_t blf;

  // cmd add
  fe range_s;
  fe range_e;
  fe stride_k;
  pe stride_p;
  pe gpoints[GROUP_INV_SIZE];
  size_t job_size;

  // cmd mul
  queue_t queue;
  bool raw_text;

  // cmd rnd
  bool has_seed;
  u32 ord_offs;
  u32 ord_size;

  // cmd scan (custom scanner)
  _Atomic bool stop_on_found;
  char matrix_keys[10][MATRIX_KEY_SIZE];
  int matrix_index;
  size_t scan_total_range;
  char target_address[TARGET_ADDR_SIZE];
} ctx_t;

// Forward declarations for new functions
void ctx_cleanup(ctx_t *ctx);
void safe_strcpy(char *dest, const char *src, size_t dest_size);
void safe_strcat(char *dest, const char *src, size_t dest_size);
bool ctx_precompute_gpoints(ctx_t *ctx);
bool calc_priv(fe pk, const fe start_pk, const fe stride_k, size_t pk_off, u8 endo);
bool batch_add(ctx_t *ctx, const fe pk, const size_t iterations);
bool batch_scan(ctx_t *ctx, const fe pk, const size_t iterations);
bool gen_random_range(ctx_t *ctx, const fe a, const fe b);
bool cmd_add(ctx_t *ctx);
bool cmd_mul(ctx_t *ctx);
bool cmd_rnd(ctx_t *ctx);
bool cmd_scan(ctx_t *ctx);
bool arg_search_range(args_t *args, fe range_s, fe range_e);
void draw_keyhunt_progress_bar(double progress, int width);
void draw_matrix_scanner(ctx_t *ctx);
void update_matrix_display(ctx_t *ctx, const fe pk);
void ctx_scan_update(ctx_t *ctx, size_t k_checked, const fe current_pk);
void check_found_scan(ctx_t *ctx, fe const start_pk, const pe *points);

// Memory cleanup function
void ctx_cleanup(ctx_t *ctx) {
  if (ctx == NULL) return;
  
  // Free allocated memory
  if (ctx->to_find_hashes != NULL) {
    free(ctx->to_find_hashes);
    ctx->to_find_hashes = NULL;
  }
  
  if (ctx->blf.bits != NULL) {
    free(ctx->blf.bits);
    ctx->blf.bits = NULL;
    ctx->blf.size = 0;
  }
  
  if (ctx->threads != NULL) {
    free(ctx->threads);
    ctx->threads = NULL;
  }
  
  // Destroy synchronization primitives
  pthread_mutex_destroy(&ctx->lock);
  pthread_cond_destroy(&ctx->pause_cond);
  
  // Close output file if it's not stdout
  if (ctx->outfile != NULL && ctx->outfile != stdout) {
    fclose(ctx->outfile);
    ctx->outfile = NULL;
  }
}

// Safe string copy function
void safe_strcpy(char *dest, const char *src, size_t dest_size) {
  if (dest == NULL || src == NULL || dest_size == 0) return;
  strncpy(dest, src, dest_size - 1);
  dest[dest_size - 1] = '\0';
}

// Safe string concatenation
void safe_strcat(char *dest, const char *src, size_t dest_size) {
  if (dest == NULL || src == NULL || dest_size == 0) return;
  size_t current_len = strnlen(dest, dest_size);
  if (current_len < dest_size - 1) {
    strncpy(dest + current_len, src, dest_size - current_len - 1);
    dest[dest_size - 1] = '\0';
  }
}

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
    if (!blf_load(filepath, &ctx->blf)) {
      fclose(file);
      exit(1);
    }
    fclose(file);
    return;
  }

  size_t hlen = sizeof(u32) * 5;
  assert(hlen == sizeof(h160_t));
  size_t capacity = 32;
  size_t size = 0;
  u32 *hashes = malloc(capacity * hlen);
  if (hashes == NULL) {
    fprintf(stderr, "memory allocation failed\n");
    fclose(file);
    exit(1);
  }

  hex40 line;
  while (fgets(line, sizeof(line), file)) {
    if (strlen(line) != sizeof(line) - 1) continue;

    if (size >= capacity) {
      capacity *= 2;
      u32 *new_hashes = realloc(hashes, capacity * hlen);
      if (new_hashes == NULL) {
        fprintf(stderr, "memory reallocation failed\n");
        free(hashes);
        fclose(file);
        exit(1);
      }
      hashes = new_hashes;
    }

    for (size_t j = 0; j < sizeof(line) - 1; j += 8) {
      if (sscanf(line + j, "%8x", &hashes[size * 5 + j / 8]) != 1) {
        fprintf(stderr, "failed to parse hash at line %zu\n", size + 1);
        continue;
      }
    }

    size += 1;
  }

  fclose(file);
  
  if (size == 0) {
    fprintf(stderr, "no valid hashes found in filter file\n");
    free(hashes);
    exit(1);
  }

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
  if (ctx->blf.bits == NULL) {
    fprintf(stderr, "failed to allocate bloom filter\n");
    free(hashes);
    ctx->to_find_hashes = NULL;
    exit(1);
  }
  memset(ctx->blf.bits, 0, ctx->blf.size * sizeof(u64));
  
  for (size_t i = 0; i < ctx->to_find_count; ++i) {
    blf_add(&ctx->blf, hashes + i * 5);
  }
}

// note: this function is not thread-safe; use mutex lock before calling
void ctx_print_unlocked(ctx_t *ctx) {
  // Only thread 0 prints in pure random mode
  if (atomic_load(&ctx->pure_random_view) && ctx->tid != 0) return;
  
  int64_t effective_time = (int64_t)(ctx->ts_updated - ctx->ts_started) - (int64_t)ctx->paused_time;
  double dt = MAX(1, effective_time) / 1000.0;
  double speed = atomic_load(&ctx->k_checked) / dt / 1000000;
  
  // KeyHunt-style Pure Random View - Clean minimal output
  if (atomic_load(&ctx->pure_random_view) && !ctx->quiet) {
    static const char spin[4] = {'|', '/', '-', '\\'};
    static int si = 0;
    
    fprintf(stderr, "\033[H\033[J"); // Clear terminal
    fprintf(stderr, "SCANNING KEY: %s %c\n", ctx->sample_key, spin[si]);
    fprintf(stderr, "SPEED: %.2f MKeys/s\n", speed);
    fprintf(stderr, "TOTAL SCANNED: %zu\n", atomic_load(&ctx->k_checked));
    fflush(stderr);
    si = (si + 1) & 3;
    
    if (atomic_load(&ctx->finished)) {
      fprintf(stderr, "\n");
    }
    
    return;
  }
  
  // Default view for other modes
  if (!ctx->quiet) {
    char key_hex[17];
    snprintf(key_hex, sizeof(key_hex), "%016llx", ctx->range_s[3]);
    printf("\rKey: %s... | Speed: %.2f MKeys/s | Total: %llu%s", 
           key_hex, speed, (unsigned long long)atomic_load(&ctx->k_checked),
           atomic_load(&ctx->finished) ? "\n" : "");
    fflush(stdout);
  }
}

void ctx_print_status(ctx_t *ctx) {
  pthread_mutex_lock(&ctx->lock);
  ctx_print_unlocked(ctx);
  pthread_mutex_unlock(&ctx->lock);
}

void ctx_check_paused(ctx_t *ctx) {
  pthread_mutex_lock(&ctx->lock);
  while (atomic_load(&ctx->paused)) {
    pthread_cond_wait(&ctx->pause_cond, &ctx->lock);
  }
  pthread_mutex_unlock(&ctx->lock);
}

void ctx_update(ctx_t *ctx, size_t k_checked) {
  size_t ts = tsnow();

  pthread_mutex_lock(&ctx->lock);
  
  // Update sample key for KeyHunt-style view (every update)
  if (atomic_load(&ctx->pure_random_view)) {
    snprintf(ctx->sample_key, sizeof(ctx->sample_key), 
             "%016llx%016llx%016llx%016llx", 
             ctx->range_s[3], ctx->range_s[2], ctx->range_s[1], ctx->range_s[0]);
  }
  
  // Update display every 20ms for KeyHunt view (smooth), 50ms for others
  bool need_print = atomic_load(&ctx->pure_random_view) 
    ? (ts - ctx->ts_printed) >= 20 
    : (ts - ctx->ts_printed) >= 50;
    
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
  ctx_print_unlocked(ctx);
  if (ctx->outfile != NULL && ctx->outfile != stdout) {
    fclose(ctx->outfile);
    ctx->outfile = NULL;
  }
  pthread_mutex_unlock(&ctx->lock);
}

void ctx_write_found(ctx_t *ctx, const char *label, const h160_t hash, const fe pk) {
  pthread_mutex_lock(&ctx->lock);

  if (!ctx->quiet) {
    if (atomic_load(&ctx->pure_random_view)) {
      // KeyHunt-style found key display - Clean text only
      fprintf(stderr, "\n\n*** KEY FOUND! ***\n");
      fprintf(stderr, "0x%016llx%016llx%016llx%016llx\n", pk[3], pk[2], pk[1], pk[0]);
      fprintf(stderr, "\n");
      fflush(stderr);
    } else {
      // Original display
      printf("\n*** KEY FOUND! ***\n");
      printf("0x%016llx%016llx%016llx%016llx\n", pk[3], pk[2], pk[1], pk[0]);
      printf("\n");
      fflush(stdout);
    }
  }

  if (ctx->outfile != NULL) {
    fprintf(ctx->outfile, "%s\t%08x%08x%08x%08x%08x\t%016llx%016llx%016llx%016llx\n", //
            label, hash[0], hash[1], hash[2], hash[3], hash[4],                       //
            pk[3], pk[2], pk[1], pk[0]);
    fflush(ctx->outfile);
  }

  atomic_fetch_add(&ctx->k_found, 1);

  pthread_mutex_unlock(&ctx->lock);
}

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

bool ctx_precompute_gpoints(ctx_t *ctx) {
  // precalc addition step with stride (2^offset)
  fe_set64(ctx->stride_k, 1);
  fe_shiftl(ctx->stride_k, ctx->ord_offs);

  fe t; // precalc stride point
  if (!fe_modn_add_stride(t, FE_ZERO, ctx->stride_k, GROUP_INV_SIZE)) {
    return false;
  }
  
  if (!ec_jacobi_mulrdc(&ctx->stride_p, &G1, t)) { // G * (GROUP_INV_SIZE * gs)
    return false;
  }

  pe g1, g2;
  if (!ec_jacobi_mulrdc(&g1, &G1, ctx->stride_k)) {
    return false;
  }
  
  if (!ec_jacobi_dblrdc(&g2, &g1)) {
    return false;
  }

  size_t hsize = GROUP_INV_SIZE / 2;

  // K+1, K+2, .., K+N/2-1
  pe_clone(ctx->gpoints + 0, &g1);
  pe_clone(ctx->gpoints + 1, &g2);
  for (size_t i = 2; i < hsize; ++i) {
    if (!ec_jacobi_addrdc(ctx->gpoints + i, ctx->gpoints + i - 1, &g1)) {
      return false;
    }
  }

  // K-1, K-2, .., K-N/2
  for (size_t i = 0; i < hsize; ++i) {
    pe_clone(&ctx->gpoints[hsize + i], &ctx->gpoints[i]);
    fe_modp_neg(ctx->gpoints[hsize + i].y, ctx->gpoints[i].y); // y = -y
  }
  
  return true;
}

bool pk_verify_hash(const fe pk, const h160_t hash, bool c, size_t endo) {
  pe point;
  if (!ec_jacobi_mulrdc(&point, &G1, pk)) {
    fprintf(stderr, "[!] error: failed to compute public key\n");
    return false;
  }

  h160_t h;
  c ? addr33(h, &point) : addr65(h, &point);

  bool is_equal = memcmp(h, hash, sizeof(h160_t)) == 0;
  if (!is_equal) {
    fprintf(stderr, "[!] error: hash mismatch (compressed: %d endo: %zu)\n", c, endo);
    fprintf(stderr, "pk: %016llx%016llx%016llx%016llx\n", pk[3], pk[2], pk[1], pk[0]);
    fprintf(stderr, "lh: %08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4]);
    fprintf(stderr, "rh: %08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4]);
    return false;
  }
  
  return true;
}

// MARK: CMD_ADD

bool calc_priv(fe pk, const fe start_pk, const fe stride_k, size_t pk_off, u8 endo) {
  if (!fe_modn_add_stride(pk, start_pk, stride_k, pk_off)) {
    return false;
  }

  if (endo == 0) return true;
  if (endo == 1) fe_modn_neg(pk, pk);
  if (endo == 2 || endo == 3) {
    if (!fe_modn_mul(pk, pk, A1)) return false;
  }
  if (endo == 3) fe_modn_neg(pk, pk);
  if (endo == 4 || endo == 5) {
    if (!fe_modn_mul(pk, pk, A2)) return false;
  }
  if (endo == 5) fe_modn_neg(pk, pk);
  
  return true;
}

void check_hash(ctx_t *ctx, bool c, const h160_t h, const fe start_pk, u64 pk_off, size_t endo) {
  if (!ctx_check_hash(ctx, h)) return;

  fe ck;
  if (!calc_priv(ck, start_pk, ctx->stride_k, pk_off, endo)) {
    fprintf(stderr, "[!] error: failed to calculate private key\n");
    return;
  }
  
  if (pk_verify_hash(ck, h, c, endo)) {
    ctx_write_found(ctx, c ? "addr33" : "addr65", h, ck);
  }
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

  // https://bitcointalk.org/index.php?topic=5527935.msg65000919#msg65000919
  // PubKeys  = (x,y) (x,-y) (x*beta,y) (x*beta,-y) (x*beta^2,y) (x*beta^2,-y)
  // PrivKeys = (pk) (!pk) (pk*alpha) !(pk*alpha) (pk*alpha^2) !(pk*alpha^2)

  size_t esize = HASH_BATCH_SIZE * 5;
  pe endos[esize];
  for (size_t i = 0; i < esize; ++i) {
    fe_set64(endos[i].z, 1);
    fe_set64(endos[i].x, 0);
    fe_set64(endos[i].y, 0);
  }

  size_t ci = 0;
  for (size_t k = 0; k < GROUP_INV_SIZE; ++k) {
    size_t idx = (k * 5) % esize;

    fe_clone(endos[idx + 0].x, points[k].x); // (x, -y)
    fe_modp_neg(endos[idx + 0].y, points[k].y);

    fe_modp_mul(endos[idx + 1].x, points[k].x, B1); // (x * beta, y)
    fe_clone(endos[idx + 1].y, points[k].y);

    fe_clone(endos[idx + 2].x, endos[idx + 1].x); // (x * beta, -y)
    fe_clone(endos[idx + 2].y, endos[idx + 0].y);

    fe_modp_mul(endos[idx + 3].x, points[k].x, B2); // (x * beta^2, y)
    fe_clone(endos[idx + 3].y, points[k].y);

    fe_clone(endos[idx + 4].x, endos[idx + 3].x); // (x * beta^2, -y)
    fe_clone(endos[idx + 4].y, endos[idx + 0].y);

    bool is_full = (idx + 5) % esize == 0 || k == GROUP_INV_SIZE - 1;
    if (!is_full) continue;

    for (size_t i = 0; i < esize; i += HASH_BATCH_SIZE) {
      if (ctx->check_addr33) addr33_batch(hs33, endos + i, HASH_BATCH_SIZE);
      if (ctx->check_addr65) addr65_batch(hs65, endos + i, HASH_BATCH_SIZE);

      for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
        // if (ci >= (GROUP_INV_SIZE * 5)) break;
        // printf(">> %6zu | %6zu ~ %zu\n", ci, ci / 5, (ci % 5) + 1);
        if (ctx->check_addr33) check_hash(ctx, true, hs33[j], start_pk, ci / 5, (ci % 5) + 1);
        if (ctx->check_addr65) check_hash(ctx, false, hs65[j], start_pk, ci / 5, (ci % 5) + 1);
        ci += 1;
      }
    }
  }

  assert(ci == GROUP_INV_SIZE * 5);
}

bool batch_add(ctx_t *ctx, const fe pk, const size_t iterations) {
  size_t hsize = GROUP_INV_SIZE / 2;

  pe bp[GROUP_INV_SIZE]; // calculated ec points
  fe dx[hsize];          // delta x for group inversion
  pe GStart;             // iteration points
  fe ck, rx, ry;         // current start point; tmp for x3, y3
  fe ss, dd;             // temp variables

  // set start point to center of the group
  if (!fe_modn_add_stride(ss, pk, ctx->stride_k, hsize)) {
    return false;
  }
  
  if (!ec_jacobi_mulrdc(&GStart, &G1, ss)) { // G * (pk + hsize * gs)
    return false;
  }

  // group addition with single inversion (with stride support)
  // structure: K-N/2 .. K-2 K-1 [K] K+1 K+2 .. K+N/2-1 (last K dropped to have odd size)
  // points in `bp` already order by `pk` increment
  fe_clone(ck, pk); // start pk for current iteration

  size_t counter = 0;
  while (counter < iterations) {
    for (size_t i = 0; i < hsize; ++i) fe_modp_sub(dx[i], ctx->gpoints[i].x, GStart.x);
    fe_modp_grpinv(dx, hsize);

    pe_clone(&bp[hsize + 0], &GStart); // set K value

    for (size_t D = 0; D < 2; ++D) {
      bool positive = D == 0;
      size_t g_idx = positive ? 0 : hsize; // plus points in first half, minus in second half
      size_t g_max = positive ? hsize - 1 : hsize; // skip K+N/2, since we don't need it
      for (size_t i = 0; i < g_max; ++i) {
        fe_modp_sub(ss, ctx->gpoints[g_idx + i].y, GStart.y); // y2 - y1
        fe_modp_mul(ss, ss, dx[i]);                           // λ = (y2 - y1) / (x2 - x1)
        fe_modp_sqr(rx, ss);                                  // λ²
        fe_modp_sub(rx, rx, GStart.x);                        // λ² - x1
        fe_modp_sub(rx, rx, ctx->gpoints[g_idx + i].x);       // rx = λ² - x1 - x2
        fe_modp_sub(dd, GStart.x, rx);                        // x1 - rx
        fe_modp_mul(dd, ss, dd);                              // λ * (x1 - rx)
        fe_modp_sub(ry, dd, GStart.y);                        // ry = λ * (x1 - rx) - y1

        // ordered by pk:
        // [0]: K-N/2, [1]: K-N/2+1, .., [N/2-1]: K-1 // all minus points
        // [N/2]: K, [N/2+1]: K+1, .., [N-1]: K+N/2-1 // K, plus points without last element
        size_t idx = positive ? hsize + i + 1 : hsize - 1 - i;
        fe_clone(bp[idx].x, rx);
        fe_clone(bp[idx].y, ry);
        fe_set64(bp[idx].z, 0x1);
      }
    }

    check_found_add(ctx, ck, bp);
    if (!fe_modn_add_stride(ck, ck, ctx->stride_k, GROUP_INV_SIZE)) { // move pk to next group START
      return false;
    }
    
    if (!ec_jacobi_addrdc(&GStart, &GStart, &ctx->stride_p)) {        // move GStart to next group CENTER
      return false;
    }
    
    counter += GROUP_INV_SIZE;
  }
  
  return true;
}

void *cmd_add_worker(void *arg) {
  ctx_t *ctx = (ctx_t *)arg;

  fe initial_r; // keep initial range start to check overflow
  fe_clone(initial_r, ctx->range_s);

  // job_size multiply by 2^offset (iterate over desired digit order)
  // for example: 3013 3023 .. 30X3 .. 3093 3103 3113
  fe inc = {0};
  fe_set64(inc, ctx->job_size);
  fe_modn_mul(inc, inc, ctx->stride_k);

  fe pk;
  while (true) {
    pthread_mutex_lock(&ctx->lock);
    bool is_overflow = fe_cmp(ctx->range_s, initial_r) < 0;
    bool range_exceeded = fe_cmp(ctx->range_s, ctx->range_e) >= 0;
    
    if (range_exceeded || is_overflow || atomic_load(&ctx->finished)) {
      pthread_mutex_unlock(&ctx->lock);
      break;
    }

    fe_clone(pk, ctx->range_s);
    fe_modn_add(ctx->range_s, ctx->range_s, inc);
    pthread_mutex_unlock(&ctx->lock);

    if (!batch_add(ctx, pk, ctx->job_size)) {
      fprintf(stderr, "[!] error in batch_add operation\n");
      break;
    }
    
    ctx_update(ctx, ctx->use_endo ? ctx->job_size * 6 : ctx->job_size);
    
    if (atomic_load(&ctx->finished)) {
      break;
    }
  }

  return NULL;
}

bool cmd_add(ctx_t *ctx) {
  if (!ctx_precompute_gpoints(ctx)) {
    fprintf(stderr, "[!] failed to precompute G points\n");
    return false;
  }

  fe range_size;
  fe_modn_sub(range_size, ctx->range_e, ctx->range_s);
  
  // Validate job size
  if (fe_cmp64(range_size, 0) <= 0) {
    fprintf(stderr, "[!] invalid range size\n");
    return false;
  }
  
  ctx->job_size = fe_cmp64(range_size, MAX_JOB_SIZE) < 0 ? range_size[0] : MAX_JOB_SIZE;
  if (ctx->job_size == 0) {
    ctx->job_size = 1;
  }
  
  ctx->ts_started = tsnow(); // actual start time

  // Create threads with error checking
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    if (pthread_create(&ctx->threads[i], NULL, cmd_add_worker, ctx) != 0) {
      fprintf(stderr, "[!] failed to create thread %zu\n", i);
      // Join already created threads
      for (size_t j = 0; j < i; ++j) {
        pthread_join(ctx->threads[j], NULL);
      }
      return false;
    }
  }

  // Wait for threads with error checking
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    if (pthread_join(ctx->threads[i], NULL) != 0) {
      fprintf(stderr, "[!] failed to join thread %zu\n", i);
    }
  }

  ctx_finish(ctx);
  return true;
}

// MARK: CMD_MUL

void check_found_mul(ctx_t *ctx, const fe *pk, const pe *cp, size_t cnt) {
  h160_t hs33[HASH_BATCH_SIZE];
  h160_t hs65[HASH_BATCH_SIZE];

  for (size_t i = 0; i < cnt; i += HASH_BATCH_SIZE) {
    size_t batch_size = MIN(HASH_BATCH_SIZE, cnt - i);
    if (ctx->check_addr33) addr33_batch(hs33, cp + i, batch_size);
    if (ctx->check_addr65) addr65_batch(hs65, cp + i, batch_size);

    for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
      if (j >= batch_size) break;
      
      if (ctx->check_addr33 && ctx_check_hash(ctx, hs33[j])) {
        if (pk_verify_hash(pk[i + j], hs33[j], true, 0)) {
          ctx_write_found(ctx, "addr33", hs33[j], pk[i + j]);
        }
      }

      if (ctx->check_addr65 && ctx_check_hash(ctx, hs65[j])) {
        if (pk_verify_hash(pk[i + j], hs65[j], false, 0)) {
          ctx_write_found(ctx, "addr65", hs65[j], pk[i + j]);
        }
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

  // sha256 routine
  u8 msg[(MAX_LINE_SIZE + 63 + 9) / 64 * 64] = {0}; // 9 = 1 byte 0x80 + 8 byte bitlen
  u32 res[8] = {0};

  fe pk[GROUP_INV_SIZE];
  pe cp[GROUP_INV_SIZE];
  cmd_mul_job_t *job = NULL;

  while (!atomic_load(&ctx->finished)) {
    if (job != NULL) {
      free(job);
      job = NULL;
    }
    
    job = queue_get(&ctx->queue);
    if (job == NULL) break;

    // parse private keys from hex string
    if (!ctx->raw_text) {
      for (size_t i = 0; i < job->count; ++i) {
        if (!fe_modn_from_hex(pk[i], job->lines[i])) {
          fprintf(stderr, "[!] invalid hex key: %s\n", job->lines[i]);
          // Skip this key
          fe_set64(pk[i], 0);
        }
      }
    } else {
      for (size_t i = 0; i < job->count; ++i) {
        size_t len = strlen(job->lines[i]);
        if (len >= MAX_LINE_SIZE) {
          fprintf(stderr, "[!] line too long, skipping: %s\n", job->lines[i]);
          fe_set64(pk[i], 0);
          continue;
        }
        
        size_t msg_size = (len + 63 + 9) / 64 * 64;
        if (msg_size > sizeof(msg)) {
          fprintf(stderr, "[!] message buffer too small\n");
          fe_set64(pk[i], 0);
          continue;
        }

        // calculate sha256 hash
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

    // compute public keys in batch
    for (size_t i = 0; i < job->count; ++i) {
      if (!ec_gtable_mul(&cp[i], pk[i])) {
        fprintf(stderr, "[!] failed to compute public key for index %zu\n", i);
        // Set to point at infinity or some error value
        fe_set64(cp[i].x, 0);
        fe_set64(cp[i].y, 0);
        fe_set64(cp[i].z, 0);
      }
    }
    
    ec_jacobi_grprdc(cp, job->count);

    check_found_mul(ctx, pk, cp, job->count);
    ctx_update(ctx, job->count);
  }

  if (job != NULL) {
    free(job);
  }
  return NULL;
}

bool cmd_mul(ctx_t *ctx) {
  if (!ec_gtable_init()) {
    fprintf(stderr, "[!] failed to initialize G table\n");
    return false;
  }

  // Create threads with error checking
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    if (pthread_create(&ctx->threads[i], NULL, cmd_mul_worker, ctx) != 0) {
      fprintf(stderr, "[!] failed to create thread %zu\n", i);
      // Join already created threads
      for (size_t j = 0; j < i; ++j) {
        pthread_join(ctx->threads[j], NULL);
      }
      return false;
    }
  }

  cmd_mul_job_t *job = calloc(1, sizeof(cmd_mul_job_t));
  if (job == NULL) {
    fprintf(stderr, "[!] failed to allocate job\n");
    queue_done(&ctx->queue);
    return false;
  }
  
  char line[MAX_LINE_SIZE];

  while (fgets(line, sizeof(line), stdin) != NULL && !atomic_load(&ctx->finished)) {
    size_t len = strlen(line);
    if (len && line[len - 1] == '\n') line[--len] = '\0';
    if (len && line[len - 1] == '\r') line[--len] = '\0';
    if (len == 0) continue;

    if (len >= MAX_LINE_SIZE) {
      fprintf(stderr, "[!] line too long, skipping: %s\n", line);
      continue;
    }
    
    safe_strcpy(job->lines[job->count], line, MAX_LINE_SIZE);
    job->count++;
    
    if (job->count == GROUP_INV_SIZE) {
      queue_put(&ctx->queue, job);
      job = calloc(1, sizeof(cmd_mul_job_t));
      if (job == NULL) {
        fprintf(stderr, "[!] failed to allocate job\n");
        break;
      }
    }
  }

  if (job != NULL) {
    if (job->count > 0 && job->count != GROUP_INV_SIZE) {
      queue_put(&ctx->queue, job);
    } else {
      free(job);
    }
  }

  queue_done(&ctx->queue);

  // Wait for threads with error checking
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    if (pthread_join(ctx->threads[i], NULL) != 0) {
      fprintf(stderr, "[!] failed to join thread %zu\n", i);
    }
  }

  ctx_finish(ctx);
  return true;
}

// MARK: CMD_RND

bool gen_random_range(ctx_t *ctx, const fe a, const fe b) {
  // Pure random mode: generate small chunk around random key for thread distribution
  if (ctx->ord_size == 0) {
    if (!fe_rand_range(ctx->range_s, a, b, !ctx->has_seed)) {
      return false;
    }
    
    fe_clone(ctx->range_e, ctx->range_s);
    
    // Create a small range for thread distribution (threads_count * job_size)
    fe chunk_size;
    fe_set64(chunk_size, ctx->threads_count * ctx->job_size);
    
    // Check for overflow
    fe temp;
    fe_modn_add(temp, ctx->range_s, chunk_size);
    if (fe_cmp(temp, b) > 0 || fe_cmp(temp, ctx->range_s) < 0) { // overflow check
      fe_clone(ctx->range_e, b);
    } else {
      fe_clone(ctx->range_e, temp);
    }
    
    // Ensure range is valid
    if (fe_cmp(ctx->range_s, ctx->range_e) >= 0) {
      fe_clone(ctx->range_e, b);
    }
    
    return true;
  }

  // Chunked random mode: generate random base with dynamic bits
  if (!fe_rand_range(ctx->range_s, a, b, !ctx->has_seed)) {
    return false;
  }
  
  fe_clone(ctx->range_e, ctx->range_s);
  for (u32 i = ctx->ord_offs; i < (ctx->ord_offs + ctx->ord_size); ++i) {
    ctx->range_s[i / 64] &= ~(1ULL << (i % 64));
    ctx->range_e[i / 64] |= 1ULL << (i % 64);
  }

  // put in bounds
  if (fe_cmp(ctx->range_s, a) <= 0) fe_clone(ctx->range_s, a);
  if (fe_cmp(ctx->range_e, b) >= 0) fe_clone(ctx->range_e, b);
  
  return true;
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

bool cmd_rnd(ctx_t *ctx) {
  ctx->ord_offs = MIN(ctx->ord_offs, 255 - ctx->ord_size);
  // Silent mode - no header output
  
  if (!ctx_precompute_gpoints(ctx)) {
    fprintf(stderr, "[!] failed to precompute G points\n");
    return false;
  }
  
  ctx->job_size = MAX_JOB_SIZE;
  ctx->ts_started = tsnow(); // actual start time

  fe range_s, range_e;
  fe_clone(range_s, ctx->range_s);
  fe_clone(range_e, ctx->range_e);

  while (!atomic_load(&ctx->finished)) {
    if (!gen_random_range(ctx, range_s, range_e)) {
      fprintf(stderr, "[!] failed to generate random range\n");
      break;
    }
    
    // Silent mode - no range printing
    ctx_print_status(ctx);

    // if full range is used, skip break after first iteration
    bool is_full = fe_cmp(ctx->range_s, range_s) == 0 && fe_cmp(ctx->range_e, range_e) == 0;

    // Create threads with error checking
    for (size_t i = 0; i < ctx->threads_count; ++i) {
      if (pthread_create(&ctx->threads[i], NULL, cmd_add_worker, ctx) != 0) {
        fprintf(stderr, "[!] failed to create thread %zu\n", i);
        // Join already created threads
        for (size_t j = 0; j < i; ++j) {
          pthread_join(ctx->threads[j], NULL);
        }
        return false;
      }
    }

    // Wait for threads with error checking
    for (size_t i = 0; i < ctx->threads_count; ++i) {
      if (pthread_join(ctx->threads[i], NULL) != 0) {
        fprintf(stderr, "[!] failed to join thread %zu\n", i);
      }
    }

    // Silent mode - no iteration stats
    
    if (is_full || atomic_load(&ctx->finished)) break;
  }

  ctx_finish(ctx);
  return true;
}

// MARK: CMD_SCAN (Matrix Scanner with Clean Exit)

void draw_keyhunt_progress_bar(double progress, int width) {
  int filled = (int)(progress * width);
  printf("[");
  for (int i = 0; i < width; i++) {
    if (i < filled) printf("=");
    else printf(" ");
  }
  printf("] %.2f%%", progress * 100);
}

void draw_matrix_scanner(ctx_t *ctx) {
  int64_t effective_time = (int64_t)(ctx->ts_updated - ctx->ts_started) - (int64_t)ctx->paused_time;
  double dt = MAX(1, effective_time) / 1000.0;
  double speed = atomic_load(&ctx->k_checked) / dt / 1000000;
  
  double progress = 0.0;
  if (ctx->scan_total_range > 0) {
    progress = (double)atomic_load(&ctx->k_checked) / (double)ctx->scan_total_range;
    if (progress > 1.0) progress = 1.0;
  }
  
  // Clear screen
  printf("\033[2J\033[H");
  
  // Current scanning key (top display)
  if (strlen(ctx->matrix_keys[0]) > 0) {
    printf("SCANNING KEY: %s\n", ctx->matrix_keys[0]);
  } else {
    printf("SCANNING KEY: initializing...\n");
  }
  
  printf("SPEED: %.2f MKeys/s\n", speed);
  printf("TOTAL SCANNED: %llu\n\n", (unsigned long long)atomic_load(&ctx->k_checked));
  
  // Matrix scrolling keys with fade
  for (int i = 0; i < 10; i++) {
    if (strlen(ctx->matrix_keys[i]) > 0) {
      int color = 46 - (i * 2);
      printf("\033[38;5;%dm%s\033[0m\n", color, ctx->matrix_keys[i]);
    } else {
      printf("\n");
    }
  }
  
  printf("\n");
  printf("Progress: ");
  draw_keyhunt_progress_bar(progress, 40);
  printf(" | Threads: %zu\n", ctx->threads_count);
  
  fflush(stdout);
}

void update_matrix_display(ctx_t *ctx, const fe pk) {
  // Scroll keys down
  for (int i = 9; i > 0; i--) {
    safe_strcpy(ctx->matrix_keys[i], ctx->matrix_keys[i-1], MATRIX_KEY_SIZE);
  }
  
  // Add new key at top
  snprintf(ctx->matrix_keys[0], MATRIX_KEY_SIZE, "%016llx%016llx%016llx%016llx", 
           pk[3], pk[2], pk[1], pk[0]);
}

void ctx_scan_update(ctx_t *ctx, size_t k_checked, const fe current_pk) {
  size_t ts = tsnow();
  
  pthread_mutex_lock(&ctx->lock);
  
  atomic_fetch_add(&ctx->k_checked, k_checked);
  ctx->ts_updated = ts;
  
  // Update matrix display at controlled rate (100ms = 10 FPS target)
  if ((ts - ctx->ts_printed) >= 100) {
    update_matrix_display(ctx, current_pk);
    ctx->ts_printed = ts;
    draw_matrix_scanner(ctx);
  }
  
  // ATOMIC: Set finished flag immediately if key found (still within mutex)
  if (atomic_load(&ctx->k_found) > 0) {
    atomic_store(&ctx->finished, true);
  }
  
  pthread_mutex_unlock(&ctx->lock);
  
  ctx_check_paused(ctx);
}

void check_found_scan(ctx_t *ctx, fe const start_pk, const pe *points) {
  h160_t hs33[HASH_BATCH_SIZE];
  h160_t hs65[HASH_BATCH_SIZE];

  for (size_t i = 0; i < GROUP_INV_SIZE; i += HASH_BATCH_SIZE) {
    if (atomic_load(&ctx->finished)) return;
    
    if (ctx->check_addr33) addr33_batch(hs33, points + i, HASH_BATCH_SIZE);
    if (ctx->check_addr65) addr65_batch(hs65, points + i, HASH_BATCH_SIZE);
    for (size_t j = 0; j < HASH_BATCH_SIZE; ++j) {
      if (ctx->check_addr33) check_hash(ctx, true, hs33[j], start_pk, i + j, 0);
      if (ctx->check_addr65) check_hash(ctx, false, hs65[j], start_pk, i + j, 0);
      
      // Stop immediately if key found
      if (atomic_load(&ctx->stop_on_found) && atomic_load(&ctx->k_found) > 0) {
        return;
      }
    }
  }

  if (!ctx->use_endo) return;

  size_t esize = HASH_BATCH_SIZE * 5;
  pe endos[esize];
  for (size_t i = 0; i < esize; ++i) {
    fe_set64(endos[i].z, 1);
    fe_set64(endos[i].x, 0);
    fe_set64(endos[i].y, 0);
  }

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
        
        // Stop immediately if key found
        if (atomic_load(&ctx->stop_on_found) && atomic_load(&ctx->k_found) > 0) {
          return;
        }
      }
    }
  }

  assert(ci == GROUP_INV_SIZE * 5);
}

bool batch_scan(ctx_t *ctx, const fe pk, const size_t iterations) {
  size_t hsize = GROUP_INV_SIZE / 2;

  pe bp[GROUP_INV_SIZE];
  fe dx[hsize];
  pe GStart;
  fe ck, rx, ry;
  fe ss, dd;

  if (!fe_modn_add_stride(ss, pk, ctx->stride_k, hsize)) {
    return false;
  }
  
  if (!ec_jacobi_mulrdc(&GStart, &G1, ss)) {
    return false;
  }

  fe_clone(ck, pk);

  size_t counter = 0;
  while (counter < iterations) {
    // CHECK STOP FLAG BEFORE EVERY ITERATION - immediate exit
    if (atomic_load(&ctx->finished)) return true;
    
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

    check_found_scan(ctx, ck, bp);
    
    // Update display with current key
    ctx_scan_update(ctx, GROUP_INV_SIZE, ck);
    
    // IMMEDIATE exit check after update
    if (atomic_load(&ctx->finished)) return true;
    
    if (!fe_modn_add_stride(ck, ck, ctx->stride_k, GROUP_INV_SIZE)) {
      return false;
    }
    
    if (!ec_jacobi_addrdc(&GStart, &GStart, &ctx->stride_p)) {
      return false;
    }
    
    counter += GROUP_INV_SIZE;
  }
  
  return true;
}

void *cmd_scan_worker(void *arg) {
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
    bool range_exceeded = fe_cmp(ctx->range_s, ctx->range_e) >= 0;
    
    if (range_exceeded || is_overflow || atomic_load(&ctx->finished)) {
      pthread_mutex_unlock(&ctx->lock);
      break;
    }

    fe_clone(pk, ctx->range_s);
    fe_modn_add(ctx->range_s, ctx->range_s, inc);
    pthread_mutex_unlock(&ctx->lock);

    if (!batch_scan(ctx, pk, ctx->job_size)) {
      fprintf(stderr, "[!] error in batch_scan operation\n");
      break;
    }
    
    // Stop if key found
    if (atomic_load(&ctx->stop_on_found) && atomic_load(&ctx->k_found) > 0) {
      break;
    }
  }

  return NULL;
}

bool cmd_scan(ctx_t *ctx) {
  atomic_store(&ctx->stop_on_found, true);
  
  // Initialize matrix display
  for (int i = 0; i < 10; i++) {
    ctx->matrix_keys[i][0] = '\0';
  }
  
  // Calculate total range
  fe range_size;
  fe_modn_sub(range_size, ctx->range_e, ctx->range_s);
  ctx->scan_total_range = range_size[0];
  
  // Silent startup - no logs, go straight to scanning
  
  if (!ctx_precompute_gpoints(ctx)) {
    fprintf(stderr, "[!] failed to precompute G points\n");
    return false;
  }

  fe_modn_sub(range_size, ctx->range_e, ctx->range_s);
  
  // Validate range size
  if (fe_cmp64(range_size, 0) <= 0) {
    fprintf(stderr, "[!] invalid range size\n");
    return false;
  }
  
  ctx->job_size = fe_cmp64(range_size, MAX_JOB_SIZE) < 0 ? range_size[0] : MAX_JOB_SIZE;
  if (ctx->job_size == 0) {
    ctx->job_size = 1;
  }
  
  ctx->ts_started = tsnow();
  ctx->ts_printed = ctx->ts_started;

  draw_matrix_scanner(ctx);

  // Create threads with error checking
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    if (pthread_create(&ctx->threads[i], NULL, cmd_scan_worker, ctx) != 0) {
      fprintf(stderr, "[!] failed to create thread %zu\n", i);
      // Join already created threads
      for (size_t j = 0; j < i; ++j) {
        pthread_join(ctx->threads[j], NULL);
      }
      return false;
    }
  }

  // Wait for threads with error checking
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    if (pthread_join(ctx->threads[i], NULL) != 0) {
      fprintf(stderr, "[!] failed to join thread %zu\n", i);
    }
  }

  pthread_mutex_lock(&ctx->lock);
  atomic_store(&ctx->finished, true);
  pthread_mutex_unlock(&ctx->lock);
  
  // Calculate final metrics
  int64_t effective_time = (int64_t)(tsnow() - ctx->ts_started) - (int64_t)ctx->paused_time;
  double elapsed_sec = MAX(1, effective_time) / 1000.0;
  double avg_kps = atomic_load(&ctx->k_checked) / elapsed_sec / 1000000;
  
  int elapsed_hours = (int)(elapsed_sec / 3600);
  int elapsed_mins = (int)((elapsed_sec - elapsed_hours * 3600) / 60);
  int elapsed_secs = (int)(elapsed_sec - elapsed_hours * 3600 - elapsed_mins * 60);
  
  // Clear screen for final message
  printf("\033[2J\033[H");
  
  if (atomic_load(&ctx->k_found) > 0) {
    printf("\n");
    printf("[ KEY FOUND ]\n");
    
    if (strlen(ctx->matrix_keys[0]) > 0) {
      printf("0x%s\n", ctx->matrix_keys[0]);
    }
    
    if (ctx->outfile != NULL && ctx->outfile != stdout) {
      fflush(ctx->outfile);
      fclose(ctx->outfile);
      ctx->outfile = NULL;
      printf("Result saved to output file\n");
    }
    
    printf("Time elapsed: %02d:%02d:%02d\n", elapsed_hours, elapsed_mins, elapsed_secs);
    printf("Total scanned: %llu keys\n", (unsigned long long)atomic_load(&ctx->k_checked));
    printf("Average speed: %.2f MKeys/s\n", avg_kps);
    printf("Exiting...\n");
    fflush(stdout);
    exit(0);
  } else {
    printf("\nScan complete. No keys found.\n");
    printf("Time elapsed: %02d:%02d:%02d\n", elapsed_hours, elapsed_mins, elapsed_secs);
    printf("Total scanned: %llu keys\n", (unsigned long long)atomic_load(&ctx->k_checked));
    printf("Average speed: %.2f MKeys/s\n", avg_kps);
    fflush(stdout);
    if (ctx->outfile != NULL && ctx->outfile != stdout) {
      fclose(ctx->outfile);
      ctx->outfile = NULL;
    }
  }
  
  return true;
}

// MARK: args helpers

bool arg_search_range(args_t *args, fe range_s, fe range_e) {
  char *raw = arg_str(args, "-r");
  if (!raw) {
    fe_set64(range_s, GROUP_INV_SIZE);
    fe_clone(range_e, FE_P);
    return true;
  }

  char *sep = strchr(raw, ':');
  if (!sep) {
    fprintf(stderr, "invalid search range, use format: -r 8000:ffff\n");
    return false;
  }

  *sep = 0;
  if (!fe_modn_from_hex(range_s, raw) || !fe_modn_from_hex(range_e, sep + 1)) {
    fprintf(stderr, "invalid hex in search range\n");
    return false;
  }

  if (fe_cmp64(range_s, GROUP_INV_SIZE) <= 0) {
    fprintf(stderr, "invalid search range, start <= %#lx\n", GROUP_INV_SIZE);
    return false;
  }

  if (fe_cmp(range_e, FE_P) > 0) {
    fprintf(stderr, "invalid search range, end > FE_P\n");
    return false;
  }

  if (fe_cmp(range_s, range_e) >= 0) {
    fprintf(stderr, "invalid search range, start >= end\n");
    return false;
  }

  return true;
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

  // Allow bits == 0 for pure random mode, otherwise enforce MIN_SIZE
  if (tmp_size == 0) {
    // Pure random mode: -d 0:0
    ctx->ord_offs = 0;
    ctx->ord_size = 0;
    return;
  }

  if (tmp_size < MIN_SIZE || tmp_size > MAX_SIZE) {
    fprintf(stderr, "invalid size, min is %d and max is %d (or 0 for pure random mode)\n", MIN_SIZE, MAX_SIZE);
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
  printf("  scan            - custom Bitcoin scanner with Matrix-style UI\n");
  printf("\nCompute options:\n");
  printf("  -f <file>       - filter file to search (list of hashes or bloom fitler)\n");
  printf("  -o <file>       - output file to write found keys (default: stdout)\n");
  printf("  -t <threads>    - number of threads to run (default: 1)\n");
  printf("  -a <addr_type>  - address type to search: c - addr33, u - addr65 (default: c)\n");
  printf("  -r <range>      - search range in hex format (example: 8000:ffff, default all)\n");
  printf("  -d <offs:size>  - bit offset and size for search (example: 128:32, default: 0:32)\n");
  printf("                    use -d 0:0 for pure random mode (no chunking)\n");
  printf("  -q              - quiet mode (no output to stdout; -o required)\n");
  printf("  -endo           - use endomorphism (default: false)\n");
  printf("\nOther commands:\n");
  printf("  blf-gen         - create bloom filter from list of hex-encoded hash160\n");
  printf("  blf-check       - check bloom filter for given hex-encoded hash160\n");
  printf("  bench           - run benchmark of internal functions\n");
  printf("  bench-gtable    - run benchmark of ecc multiplication (with different table size)\n");
  printf("\n");
}

bool init(ctx_t *ctx, args_t *args) {
  // Initialize ctx to zero
  memset(ctx, 0, sizeof(ctx_t));
  
  // check other commands first
  if (args->argc > 1) {
    if (strcmp(args->argv[1], "blf-gen") == 0) {
      blf_gen(args);
      return false; // Don't continue with normal execution
    }
    if (strcmp(args->argv[1], "blf-check") == 0) {
      blf_check(args);
      return false;
    }
    if (strcmp(args->argv[1], "bench") == 0) {
      run_bench();
      return false;
    }
    if (strcmp(args->argv[1], "bench-gtable") == 0) {
      run_bench_gtable();
      return false;
    }
    if (strcmp(args->argv[1], "mult-verify") == 0) {
      mult_verify();
      return false;
    }
  }

  ctx->use_color = isatty(fileno(stdout));

  ctx->cmd = CMD_NIL; // default show help
  if (args->argc > 1) {
    if (strcmp(args->argv[1], "add") == 0) ctx->cmd = CMD_ADD;
    if (strcmp(args->argv[1], "mul") == 0) ctx->cmd = CMD_MUL;
    if (strcmp(args->argv[1], "rnd") == 0) ctx->cmd = CMD_RND;
    if (strcmp(args->argv[1], "scan") == 0) ctx->cmd = CMD_SCAN;
  }

  if (ctx->cmd == CMD_NIL) {
    if (args_bool(args, "-v")) printf("ecloop v%s\n", VERSION);
    else usage(args->argv[0]);
    return false;
  }

  // Initialize synchronization primitives
  if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
    fprintf(stderr, "failed to initialize mutex\n");
    return false;
  }
  
  if (pthread_cond_init(&ctx->pause_cond, NULL) != 0) {
    fprintf(stderr, "failed to initialize condition variable\n");
    pthread_mutex_destroy(&ctx->lock);
    return false;
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
  if (outfile) {
    ctx->outfile = fopen(outfile, "a");
    if (ctx->outfile == NULL) {
      fprintf(stderr, "failed to open output file: %s\n", outfile);
      return false;
    }
  } else {
    ctx->outfile = stdout;
  }

  if (outfile == NULL && ctx->quiet) {
    fprintf(stderr, "quiet mode chosen without output file\n");
    return false;
  }

  char *addr = arg_str(args, "-a");
  if (addr) {
    ctx->check_addr33 = strstr(addr, "c") != NULL;
    ctx->check_addr65 = strstr(addr, "u") != NULL;
    free(addr);
  }

  if (!ctx->check_addr33 && !ctx->check_addr65) {
    ctx->check_addr33 = true; // default to addr33
  }

  ctx->use_endo = args_bool(args, "-endo");
  if (ctx->cmd == CMD_MUL) ctx->use_endo = false; // no endo for mul command

  int cpus = get_cpu_count();
  ctx->threads_count = MIN(MAX(args_uint(args, "-t", cpus), 1ul), 320ul);
  ctx->threads = malloc(ctx->threads_count * sizeof(pthread_t));
  if (ctx->threads == NULL) {
    fprintf(stderr, "failed to allocate threads array\n");
    return false;
  }
  
  atomic_store(&ctx->finished, false);
  atomic_store(&ctx->paused, false);
  atomic_store(&ctx->k_checked, 0);
  atomic_store(&ctx->k_found, 0);
  atomic_store(&ctx->pure_random_view, false);
  atomic_store(&ctx->stop_on_found, false);
  
  ctx->ts_started = tsnow();
  ctx->ts_updated = ctx->ts_started;
  ctx->ts_printed = ctx->ts_started - 5e3;
  ctx->paused_time = 0;

  if (!arg_search_range(args, ctx->range_s, ctx->range_e)) {
    return false;
  }
  
  load_offs_size(ctx, args);
  
  if (!queue_init(&ctx->queue, ctx->threads_count * 3)) {
    fprintf(stderr, "failed to initialize queue\n");
    return false;
  }

  // Enable KeyHunt-style view for pure random mode (-d 0:0)
  atomic_store(&ctx->pure_random_view, (ctx->ord_size == 0 && ctx->cmd == CMD_RND));
  ctx->tid = 0; // Main thread is 0
  
  // Initialize sample_key
  safe_strcpy(ctx->sample_key, 
             "0000000000000000000000000000000000000000000000000000000000000000",
             sizeof(ctx->sample_key));

  // Initialize matrix keys for scan mode
  for (int i = 0; i < 10; i++) {
    ctx->matrix_keys[i][0] = '\0';
  }

  // Silent mode - no initialization output
  
  if (ctx->cmd == CMD_MUL) {
    ctx->raw_text = args_bool(args, "-raw");
  }
  
  // Initialize scan mode fields
  ctx->target_address[0] = '\0';
  ctx->matrix_index = 0;
  ctx->scan_total_range = 0;
  
  return true;
}

void handle_sigint(int sig) {
  fflush(stderr);
  fflush(stdout);
  printf("\n");
  exit(sig);
}

void tty_cb(void *ctx_raw, const char ch) {
  ctx_t *ctx = (ctx_t *)ctx_raw;

  if (ch == 'p' && !atomic_load(&ctx->paused)) {
    pthread_mutex_lock(&ctx->lock);
    ctx->ts_paused_at = tsnow();
    atomic_store(&ctx->paused, true);
    pthread_mutex_unlock(&ctx->lock);
    ctx_print_status(ctx);
  }

  if (ch == 'r' && atomic_load(&ctx->paused)) {
    pthread_mutex_lock(&ctx->lock);
    atomic_store(&ctx->paused, false);
    ctx->paused_time += tsnow() - ctx->ts_paused_at;
    pthread_cond_broadcast(&ctx->pause_cond);
    pthread_mutex_unlock(&ctx->lock);
    ctx_print_status(ctx);
  }
}

int main(int argc, const char **argv) {
  // https://stackoverflow.com/a/11695246
  setlocale(LC_NUMERIC, ""); // for comma separated numbers
  args_t args = {argc, argv};

  ctx_t ctx;
  if (!init(&ctx, &args)) {
    ctx_cleanup(&ctx);
    return 1;
  }

  signal(SIGINT, handle_sigint); // Keep last progress line on Ctrl-C
  tty_init(tty_cb, &ctx);        // override tty to handle pause/resume

  bool success = false;
  if (ctx.cmd == CMD_ADD) success = cmd_add(&ctx);
  if (ctx.cmd == CMD_MUL) success = cmd_mul(&ctx);
  if (ctx.cmd == CMD_RND) success = cmd_rnd(&ctx);
  if (ctx.cmd == CMD_SCAN) success = cmd_scan(&ctx);

  ctx_cleanup(&ctx);
  return success ? 0 : 1;
}
