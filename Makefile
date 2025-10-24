.PHONY: default clean build bench fmt add mul rnd blf remote

CC = cc
CC_FLAGS ?= -O3 -ffast-math -Wall -Wextra

ifeq ($(shell uname -m),x86_64)
CC_FLAGS += -march=native -pthread -lpthread
endif

CC_FLAGS += -lssl -lcrypto

# Add OpenSSL libraries for true random mode
CC_FLAGS += -lssl -lcrypto

default: build

clean:
\t@rm -rf ecloop bench main a.out *.profraw *.profdata

build: clean
\t$(CC) $(CC_FLAGS) main.c -o ecloop

bench: build
\t./ecloop bench

fmt:
\t@find . -name '*.c' | xargs clang-format -i

# -----------------------------------------------------------------------------

add: build
\t./ecloop add -f data/btc-puzzles-hash -r 8000:ffffff

mul: build
\tcat data/btc-bw-priv | ./ecloop mul -f data/btc-bw-hash -a cu -q -o /dev/null

rnd: build
\t./ecloop rnd -f data/btc-puzzles-hash -r 800000000000000000:ffffffffffffffffff -d 0:32

# Add true random mode test
rnd-true: build
\t./ecloop rnd -f data/btc-puzzles-hash -r 800000000000000000:ffffffffffffffffff -d 0:0 -t 4

blf: build
\t@rm -rf /tmp/test.blf
\t@printf "
> "
\tcat data/btc-puzzles-hash | ./ecloop blf-gen -n 32768 -o /tmp/test.blf
\t@printf "
> "
\tcat data/btc-bw-hash | ./ecloop blf-gen -n 32768 -o /tmp/test.blf
\t@printf "
> "
\t./ecloop add -f /tmp/test.blf -r 8000:ffffff -q -o /dev/null
\t@printf "
> "
\tcat data/btc-bw-priv | ./ecloop mul -f /tmp/test.blf -a cu -q -o /dev/null

verify: build
\t./ecloop mult-verify

# -----------------------------------------------------------------------------
# https://btcpuzzle.info/puzzle

range_28 = 8000000:fffffff
range_32 = 80000000:ffffffff
range_33 = 100000000:1ffffffff
range_34 = 200000000:3ffffffff
range_35 = 400000000:7ffffffff
range_36 = 800000000:fffffffff
range_71 = 400000000000000000:7fffffffffffffffff
range_72 = 800000000000000000:ffffffffffffffffff
range_73 = 1000000000000000000:1ffffffffffffffffff
range_74 = 2000000000000000000:3ffffffffffffffffff
range_76 = 8000000000000000000:fffffffffffffffffff
range_77 = 10000000000000000000:1fffffffffffffffffff
range_78 = 20000000000000000000:3fffffffffffffffffff
range_79 = 40000000000000000000:7fffffffffffffffffff
_RANGES_ = $(foreach r,$(filter range_%,$(.VARIABLES)),$(patsubst range_%,%,$r))

puzzle: build
\t@$(if $(filter $(_RANGES_),$(n)),,$(error "Invalid range $(n)"))
\t./ecloop rnd -f data/btc-puzzles-hash -d 0:32 -r $(range_$(n)) -o ./found_$(n).txt

# True random mode for puzzles (use -d 0:0)
puzzle-true: build
\t@$(if $(filter $(_RANGES_),$(n)),,$(error "Invalid range $(n)"))
\t./ecloop rnd -f data/btc-puzzles-hash -d 0:0 -r $(range_$(n)) -o ./found_$(n).txt

%:
\t@$(if $(filter $(_RANGES_),$@),make --no-print-directory puzzle n=$@,)

# -----------------------------------------------------------------------------

host=mele
cmd=add

remote:
\t@rsync -arc --progress --delete-after --exclude={'ecloop','found*.txt','.git'} ./ $(host):/tmp/ecloop
\t@ssh -tt $(host) 'clear; $(CC) --version'
\tssh -tt $(host) 'cd /tmp/ecloop; make $(cmd) CC=$(CC)'

bench-compare:
\t@ssh -tt $(host) " \
\tcd /tmp; rm -rf ecloop keyhunt; \
\tcd /tmp && git clone https://github.com/vladkens/ecloop.git && cd ecloop && make CC=clang; \
\techo '--------------------------------------------------'; \
\tcd /tmp && git clone https://github.com/albertobsd/keyhunt.git && cd keyhunt && make; \
\techo '--------------------------------------------------'; \
\tcd /tmp; \
\techo '--- t=1 (keyhunt)'; \
\ttime ./keyhunt/keyhunt -m rmd160 -f ecloop/data/btc-bw-hash -r 8000:fffffff -t 1 -n 16777216; \
\techo '--- t=1 (ecloop)'; \
\ttime ./ecloop/ecloop add -f ecloop/data/btc-bw-hash -t 1 -r 8000:fffffff; \
\techo '--- t=4 (keyhunt)'; \
\ttime ./keyhunt/keyhunt -m rmd160 -f ecloop/data/btc-bw-hash -r 8000:fffffff -t 4 -n 16777216; \
\techo '--- t=4 (ecloop)'; \
\ttime ./ecloop/ecloop add -f ecloop/data/btc-bw-hash -t 4 -r 8000:fffffff; \
\t"
