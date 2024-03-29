# Edit to fit needs
CC       = clang-11
LIB_H    =
LIB_C    =
DEFINES  =
SANS     = undefined,address,leak
WARNS    = all pedantic extra no-unused-command-line-argument
OPTIMIZE = -O3
OUTPUT   = scan
ENV      = ASAN_OPTIONS=fast_unwind_on_malloc=0 LSAN_OPTIONS=report_objects=1
ARGS     = wlan0

# Shouldn't really be touched
HDRDIR  = include
HDREXT  = .h
SRCDIR  = src
SRCEXT  = .c
OBJDIR  = objects
OBJEXT  = .o
TSTDIR  = test
LIBDIR  = lib
DEPS    = $(basename $(notdir $(wildcard $(HDRDIR)/*$(HDREXT))))
INPUTS  = $(basename $(notdir $(wildcard $(SRCDIR)/*$(SRCEXT))))
HEADERS = $(addprefix $(HDRDIR)/, $(addsuffix $(HDREXT), $(DEPS)))
SOURCES = $(addprefix $(SRCDIR)/, $(addsuffix $(SRCEXT), $(INPUTS)))
OBJECTS = $(addprefix $(OBJDIR)/, $(addsuffix $(OBJEXT), $(INPUTS)))
CFLAGS  = $(addprefix -D, $(DEFINES)) -I$(HDRDIR) -c -o
LDFLAGS = -L$(LIBDIR) -o
SHARED  = $(addprefix lib, $(addsuffix .so, $(OUTPUT)))

# Calling run without building will build
# without optimizations and without debug flags
.PHONY: debug
.PHONY: release
.PHONY: library
.PHONY: build
.PHONY: run
.PHONY: clean

# Silence command names
$(VERBOSE).SILENT:

# Build with warnings, sanitizers and DEBUG flags
debug: DEFINES := DEBUG $(DEFINES)
debug: CFLAGS  := -g $(addprefix -W, $(WARNS)) $(CFLAGS)
debug: LDFLAGS := -g -fsanitize=$(SANS) $(LDFLAGS)
debug: initialize
debug: $(OUTPUT)

# Build with optimizers and NDEBUG flags
release: DEFINES := NDEBUG $(DEFINES)
release: CFLAGS  := $(OPTIMIZE) $(CFLAGS)
release: LDFLAGS := $(LDFLAGS)
release: initialize
release: $(OUTPUT)

# Build release but for use as a shared library
library: DEFINES := NDEBUG $(DEFINES)
library: CFLAGS  := -fPIC $(OPTIMIZE) $(CFLAGS)
library: LDFLAGS := -fPIC -shared $(LDFLAGS)
library: initialize
library: $(SHARED)

# Sets up project structure
initialize: | $(HDRDIR) $(SRCDIR) $(OBJDIR) $(TSTDIR) $(LIBDIR)

# Run executable with args
run: $(OUTPUT)
	$(ENV) ./$(OUTPUT) $(ARGS)

# Clean up generated executable and object files
clean:
	rm $(OBJECTS) $(OUTPUT) $(SHARED)

# Link libraries and build shared library
$(SHARED): $(OBJECTS)
	$(CC) $(LDFLAGS) $@ $^ $(addprefix -l, $(LIB_C))

# Link libraries and build executables
$(OUTPUT): $(OBJECTS)
	@echo "Building $@"
	$(CC) $(LDFLAGS) $@ $^ $(addprefix -l, $(LIB_C))

# Link header-only libraries and build object files
$(OBJDIR)/%$(OBJEXT): $(SRCDIR)/%$(SRCEXT)
	@echo "Building $@"
	$(CC) $(CFLAGS) $@ $< $(addprefix -l, $(LIB_H))

# Generate necessary directories
$(HDRDIR) $(SRCDIR) $(OBJDIR) $(TSTDIR) $(LIBDIR): % :
	mkdir -p $@
