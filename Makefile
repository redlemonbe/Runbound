# Runbound build system
# Requires: cargo, llvm-profdata (from clang/llvm-tools-preview)
#
# Install llvm tools:
#   rustup component add llvm-tools-preview
#
# Usage:
#   make              — debug build
#   make release      — optimised release build
#   make pgo          — profile-guided optimised build (+10–20 % QPS)
#   make bench        — quick dnsperf benchmark (requires dnsperf + running server)
#   make install      — install as systemd service (requires root)

BINARY    := target/release/runbound
PGO_DIR   := /tmp/runbound-pgo
MERGED    := $(PGO_DIR)/merged.profdata
QUERIES   := bench/queries.txt
BENCH_DUR := 30
BENCH_QPS := 150000

.PHONY: all build release pgo pgo-instrument pgo-merge pgo-optimise \
        bench install clean

# ── Default ───────────────────────────────────────────────────────────────────
all: build

build:
	cargo build

release:
	cargo build --release

# ── PGO — three-step pipeline ─────────────────────────────────────────────────
#
# How PGO works:
#   1. Instrumented build  — compiler inserts counters in every branch
#   2. Profiling run       — real traffic writes which branches are hottest
#   3. Optimised build     — compiler reorders code so the hot path lands in
#                            the CPU instruction-cache's first cache line,
#                            eliminating branch-predictor misses on most queries
#
# Result: +10–20 % raw QPS without changing a single line of application code.

pgo: pgo-instrument pgo-profile pgo-merge pgo-optimise
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo " PGO build complete: $(BINARY)"
	@echo " Run 'make bench' to measure the improvement."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

pgo-instrument:
	@echo "▶ Step 1/3 — Instrumented build (profiling counters injected)..."
	@mkdir -p $(PGO_DIR)
	RUSTFLAGS="-Cprofile-generate=$(PGO_DIR)" \
	    cargo build --release
	@echo "  Done: $(BINARY) (instrumented — ~20% slower, for profiling only)"

# This step is interactive: it starts the server, runs dnsperf, then stops it.
pgo-profile: $(BINARY)
	@echo ""
	@echo "▶ Step 2/3 — Collecting profile data..."
	@echo "  Starting Runbound in background (instrumented build)..."
	@$(BINARY) /etc/runbound/unbound.conf &
	@sleep 1
	@if ! command -v dnsperf > /dev/null 2>&1; then \
	    echo "  [WARN] dnsperf not found — generating synthetic queries instead"; \
	    $(MAKE) _pgo-synthetic-profile; \
	else \
	    echo "  Running dnsperf for $(BENCH_DUR)s at $(BENCH_QPS) QPS..."; \
	    dnsperf -s 127.0.0.1 -d $(QUERIES) -Q $(BENCH_QPS) -l $(BENCH_DUR) || true; \
	fi
	@echo "  Stopping instrumented server..."
	@pkill -f "runbound.*unbound.conf" 2>/dev/null || true
	@sleep 1
	@echo "  Profile data written to $(PGO_DIR)/"

# Fallback when dnsperf is unavailable: use dig in a tight loop
_pgo-synthetic-profile:
	@echo "  Synthetic profiling: 50 000 queries via dig..."
	@for i in $$(seq 1 10000); do \
	    dig +short @127.0.0.1 google.com A    > /dev/null 2>&1; \
	    dig +short @127.0.0.1 cloudflare.com AAAA > /dev/null 2>&1; \
	    dig +short @127.0.0.1 github.com A    > /dev/null 2>&1; \
	    dig +short @127.0.0.1 example.com MX  > /dev/null 2>&1; \
	    dig +short @127.0.0.1 rust-lang.org A > /dev/null 2>&1; \
	done

pgo-merge:
	@echo ""
	@echo "▶ Step 3a/3 — Merging profile data..."
	@# llvm-profdata may be in the rustup toolchain or system llvm
	@LLVM_PROFDATA=$$(find $$(rustup toolchain list -v | grep default | awk '{print $$2}') \
	    -name "llvm-profdata" 2>/dev/null | head -1); \
	if [ -z "$$LLVM_PROFDATA" ]; then \
	    LLVM_PROFDATA=$$(command -v llvm-profdata 2>/dev/null); \
	fi; \
	if [ -z "$$LLVM_PROFDATA" ]; then \
	    echo "  [ERROR] llvm-profdata not found."; \
	    echo "  Install with: rustup component add llvm-tools-preview"; \
	    exit 1; \
	fi; \
	echo "  Using: $$LLVM_PROFDATA"; \
	$$LLVM_PROFDATA merge -output=$(MERGED) $(PGO_DIR)/*.profraw
	@echo "  Merged: $(MERGED)"

pgo-optimise:
	@echo ""
	@echo "▶ Step 3b/3 — Final optimised build with profile data..."
	RUSTFLAGS="-Cprofile-use=$(MERGED) -Cllvm-args=-pgo-warn-missing-function" \
	    cargo build --release
	@echo "  Done: $(BINARY) (PGO-optimised)"

# ── Benchmark ─────────────────────────────────────────────────────────────────

bench:
	@if ! command -v dnsperf > /dev/null 2>&1; then \
	    echo "[ERROR] dnsperf not installed. On Debian/Ubuntu:"; \
	    echo "        apt install dnsperf"; \
	    exit 1; \
	fi
	@if [ ! -f $(QUERIES) ]; then \
	    echo "[WARN] No query file at $(QUERIES) — using built-in queries"; \
	    mkdir -p bench; \
	    printf "google.com A\ncloudflare.com AAAA\ngithub.com A\nexample.com MX\nrust-lang.org A\n" | \
	        awk 'BEGIN{for(i=0;i<2000;i++) {getline line < "/dev/stdin"; print line}}' \
	        > $(QUERIES) 2>/dev/null || \
	    for i in $$(seq 10000); do \
	        echo "google.com A"; echo "cloudflare.com A"; \
	    done > $(QUERIES); \
	fi
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo " Benchmarking Runbound at 127.0.0.1:53 for $(BENCH_DUR)s"
	@echo " Target: $(BENCH_QPS) QPS"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	dnsperf -s 127.0.0.1 -d $(QUERIES) -Q $(BENCH_QPS) -l $(BENCH_DUR)

# ── Install ───────────────────────────────────────────────────────────────────

install: release
	sudo ./install.sh

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf $(PGO_DIR)
