CXX      := g++

CXXFLAGS := -std=c++17 -Ofast \
            -funroll-loops -ftree-vectorize \
            -fstrict-aliasing -fno-semantic-interposition \
            -fvect-cost-model=unlimited -fno-trapping-math \
            -fipa-ra -fipa-modref -flto=auto \
            -fassociative-math -fopenmp \
            -mavx2 -mbmi2 -madx -march=native \
            -Wno-write-strings \
            -ffunction-sections -fdata-sections \
            -fprefetch-loop-arrays \
            -fbranch-target-load-optimize2 \
            -fexceptions

LDFLAGS  := -Wl,--gc-sections

LDLIBS   :=

SRCS     := KeyQuest.cpp SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp \
            ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp

OBJS     := $(SRCS:.cpp=.o)

TARGET   := KeyQuest

.PHONY: all clean fix_rdtsc

all: fix_rdtsc $(TARGET)

fix_rdtsc:
	find . -type f -name '*.cpp' -exec sed -i 's/__rdtsc/my_rdtsc/g' {} +

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
	rm -f $(OBJS)
	chmod +x $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@echo "Cleaning..."
	rm -f $(OBJS) $(TARGET)
