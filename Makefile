.PHONY: default clean build bench fmt add mul rnd blf remote

CC = cc
CC_FLAGS ?= -O3 -ffast-math -Wall -Wextra

ifeq ($(shell uname -m),x86_64)
CC_FLAGS += -march=native -pthread -lpthread
endif

# Add OpenSSL libraries for true random mode
CC_FLAGS += -lssl -lcrypto

default: build

clean:
	@rm -rf ecloop bench main a.out *.profraw *.profdata

build: clean
	$(CC) $(CC_FLAGS) main.c -o ecloop

bench: build
	./ecloop bench

fmt:
	@find . -name '*.c' | xargs clang-format -i

# -----------------------------------------------------------------------------

add: build
	./ecloop add -f data/btc-puzzles-hash -r 8000:ffffff

mul: build
	cat data/btc-bw-priv | ./ecloop mul -f data/btc-bw-hash -a cu -q -o /dev/null

rnd: build
	./ecloop rnd -f data/btc-puzzles-hash -r 800000000000000000:ffffffffffffffffff -d 0:32

# Add true random mode test
rnd-true: build
	./ecloop rnd -f data/btc-puzzles-hash -r 800000000000000000:ffffffffffffffffff -d 0:0 -t 4

blf: build
	@rm -rf /tmp/test.blf
	@printf "\n> "
	cat data/btc-puzzles-hash | ./ecloop blf-gen -n 32768 -o /tmp/test.blf
	@printf "\n> "
	cat data/btc-bw-hash | ./ecloop blf-gen -n 32768 -o /tmp/test.blf
	@printf "\n> "
	./ecloop add -f /tmp/test.blf -r 8000:ffffff -q -o /dev/null
	@printf "\n> "
	cat data/btc-bw-priv | ./ecloop mul -f /tmp/test.blf -a cu -q -o /dev/null

verify: build
	./ecloop mult-verify

# -----------------------------------------------------------------------------

range_72 = 800000000000000000:ffffffffffffffffff

puzzle: build
	./ecloop rnd -f data/btc-puzzles-hash -d 0:32 -r $(range_72) -o found_72.txt

puzzle-true: build
	./ecloop rnd -f data/btc-puzzles-hash -d 0:0 -r $(range_72) -o found_72.txt
