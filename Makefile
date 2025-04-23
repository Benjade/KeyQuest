# Detect OS
UNAME_S := $(shell uname -s)

# Compiler
CXX := g++

# Common compiler flags matching votre commande habituelle
CXXFLAGS := -std=c++17 -Ofast \
            -funroll-loops -ftree-vectorize \
            -fstrict-aliasing -fno-semantic-interposition \
            -fvect-cost-model=unlimited -fno-trapping-math \
            -fipa-ra -fipa-modref -flto=auto \
            -fassociative-math -fopenmp \
            -mavx2 -mbmi2 -madx -march=native \
            -Wno-write-strings

# Bibliothèques à lier
LDLIBS := -lcrypto

# Sources listées exactement comme dans votre appel g++
SRCS := KeyQuest.cpp SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp \
        ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp

# Génère la liste des .o
OBJS := $(SRCS:.cpp=.o)

# Nom de l’exécutable selon l’OS
ifeq ($(UNAME_S),Linux)
TARGET := KeyQuest
else
TARGET := KeyQuest.exe
endif

.PHONY: all clean fix_rdtsc

# Cible par défaut
all: fix_rdtsc $(TARGET)

# Remplacement de __rdtsc par my_rdtsc
fix_rdtsc:
	find . -type f -name '*.cpp' -exec sed -i 's/__rdtsc/my_rdtsc/g' {} +

# Link + suppression des .o + permission d’exécution
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDLIBS)
	rm -f $(OBJS)
	chmod +x $(TARGET)

# Compilation des .cpp en .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Nettoyage
clean:
	@echo "Cleaning..."
	rm -f $(OBJS) $(TARGET)