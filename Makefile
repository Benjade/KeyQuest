###############################################################################
# KeyQuest V1.3 – "portableperf" Makefile
#
# Quick Options
# CPU = instruction set (native|generic|znver1|skylake‑avx512…)
# e.g., make CPU=generic
# PROF = (empty) → release build
# dev → debug build (-g -O0)
# pgo → build + PGO (2 passes) [pgo target]
# LTO = 1 (default) | 0 to disable -flto
###############################################################################

### ───────────────────── User config
CPU   ?= native
PROF  ?=
LTO   ?= 1

CXX  ?= g++

SRC  = KeyQuest.cpp SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp \
       ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp
OBJ  = $(SRC:.cpp=.o)
BIN  = KeyQuest

### ───────────── common options (always active)
BASEFLAGS = -std=c++17 -Ofast -pipe                     \
            -funroll-loops -fstrict-aliasing            \
            -ffunction-sections -fdata-sections         \
            -fno-semantic-interposition                 \
            -fassociative-math -fno-trapping-math       \
            -fopenmp -Wno-write-strings                 \
            -fomit-frame-pointer                        \
            -march=$(CPU)

# Explicit ISA (AVX2…) – disable if compiling for “generic”
CPU_ISA := -mavx2 -mbmi2 -madx -mfma

# LTO
ifeq ($(LTO),1)
  BASEFLAGS += -flto=auto
  LDOPT     += -flto=auto
endif

### ───────────── Automatic linker selection
# order: mold › lld › gold › bfd ; otherwise nothing
# we test for the presence of the corresponding binary
ifneq (,$(shell command -v mold 2>/dev/null))
  LD_IMPL = mold
else ifneq (,$(shell command -v ld.lld 2>/dev/null))
  LD_IMPL = lld
else ifneq (,$(shell command -v ld.gold 2>/dev/null))
  LD_IMPL = gold
else ifneq (,$(shell command -v ld.bfd 2>/dev/null))
  LD_IMPL = bfd
else
  LD_IMPL =
endif

ifneq ($(LD_IMPL),)
  LDOPT += -fuse-ld=$(LD_IMPL)
endif

LDOPT += -Wl,--gc-sections

### ───────────── Compilation profiles
ifeq ($(PROF),dev)                 # debug
  CXXFLAGS = -g -O0 $(CPU_ISA) $(BASEFLAGS)
else ifeq ($(PROF),pgo-gen)        # passe 1 PGO
  CXXFLAGS = -fprofile-generate $(CPU_ISA) $(BASEFLAGS)
else ifeq ($(PROF),pgo-use)        # passe 2 PGO
  CXXFLAGS = -fprofile-use -fprofile-correction $(CPU_ISA) $(BASEFLAGS)
else                               # release
  CXXFLAGS = $(CPU_ISA) $(BASEFLAGS)
endif

LDFLAGS = $(LDOPT)

###############################################################################
#  Targets
###############################################################################
.PHONY: all clean dev pgo pgo-gen pgo-run pgo-use fix_rdtsc

all: fix_rdtsc $(BIN)

dev:  PROF=dev
dev:  all

# ----------  PGO (2 passes)  ----------
pgo: pgo-gen pgo-run
	@$(MAKE) PROF=pgo-use

pgo-gen: PROF=pgo-gen
pgo-gen: clean all

# short run to collect profiles (adapt duration if needed)
pgo-run:
	@echo ">>  PGO phase – 60s execution ..."
	@./$(BIN) -b 4096 & PID=$$! ; sleep 60 ; kill $$PID 2>/dev/null || true

# ----------  Build / rules ------------
$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^
	@rm -f $(OBJ)
	@chmod +x $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# replace __rdtsc with my_rdtsc (avoids unsupported asm under KVM/QEMU)
fix_rdtsc:
	@find . -type f -name '*.cpp' -exec \
	    sed -i 's/__rdtsc/my_rdtsc/g' {} +

clean:
	@echo "Cleaning..."
	@rm -f $(OBJ) $(BIN) *.gcda *.gcno *.profraw *.profdata
