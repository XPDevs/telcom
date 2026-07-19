CLANG := clang
CFLAGS := -g -O2 -Wall
BPF_TARGET := bpf
BPF_CFLAGS := -g -O2 -target $(BPF_TARGET)
INCLUDES := -I include
LIBS := -l:libbpf.so.1 -lelf -lz

VMLINUX_H := include/vmlinux.h
VERSION_H := include/version.h
VERSION_FILE := VERSION
KERNEL_HEADERS := /usr/include/linux/bpf.h

BPF_OBJ := bpf/telcom_kern.bpf.o
TC_OBJ := bpf/telcom_tc.bpf.o
DAEMON_BIN := bin/telcomd
PEEK_BIN := bin/telcom-peek

.PHONY: all check clean vmlinux version \
        build_bpf build_tc build_daemon build_tools \
        install package

all: check build_bpf build_tc build_daemon build_tools

check:
	@echo "=== Environment Checks ==="
	@FAIL=0; \
	\
	if ! command -v $(CLANG) >/dev/null 2>&1; then \
		echo "FAIL: $(CLANG) not found"; \
		FAIL=1; \
	else \
		VER=$$($(CLANG) --version | head -1 | sed 's/.*version \([0-9]*\)\..*/\1/'); \
		if [ "$$VER" -lt 11 ] 2>/dev/null; then \
			echo "FAIL: $(CLANG) version $$VER is too old (need >= 11)"; \
			FAIL=1; \
		else \
			echo "OK: $(CLANG) version $$VER"; \
		fi; \
	fi; \
	\
	if [ ! -f $(KERNEL_HEADERS) ]; then \
		echo "FAIL: kernel headers not found at $(KERNEL_HEADERS)"; \
		FAIL=1; \
	else \
		echo "OK: kernel headers found"; \
	fi; \
	\
	if [ ! -f $(VMLINUX_H) ]; then \
		if command -v bpftool >/dev/null 2>&1; then \
			if [ -f /sys/kernel/btf/vmlinux ]; then \
				echo "OK: vmlinux.h can be generated via 'make vmlinux'"; \
			else \
				echo "FAIL: vmlinux.h not found and /sys/kernel/btf/vmlinux missing"; \
				FAIL=1; \
			fi; \
		else \
			echo "FAIL: vmlinux.h not found and bpftool not available"; \
			FAIL=1; \
		fi; \
	else \
		echo "OK: vmlinux.h found"; \
	fi; \
	\
	if [ "$$FAIL" -eq 1 ]; then \
		echo ""; \
		echo "Some checks FAILED. Fix the issues above before proceeding."; \
		exit 1; \
	else \
		echo "All checks PASSED."; \
	fi

version: $(VERSION_H)

$(VERSION_H): $(VERSION_FILE)
	@echo "Generating $@ from $<"
	@printf '#ifndef __TELCOM_VERSION_H\n#define __TELCOM_VERSION_H\n\n#define TELCOM_VERSION "%s"\n\n#endif\n' \
	  "$$(cat $(VERSION_FILE) | tr -d ' \n')" > $@

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "Generating $@ from BTF..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "FAIL: /sys/kernel/btf/vmlinux not found"; \
		exit 1; \
	fi

$(BPF_OBJ): bpf/telcom_kern.c $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c -o $@ $<

build_bpf: $(BPF_OBJ)
	@echo "BPF object compiled: $<"

$(TC_OBJ): bpf/telcom_tc.c $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c -o $@ $<

build_tc: $(TC_OBJ)
	@echo "TC object compiled: $<"

bin:
	mkdir -p bin

$(DAEMON_BIN): src/telcomd.c include/telcom_kern_shared.h $(VERSION_H) | bin
	$(CLANG) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

build_daemon: $(DAEMON_BIN) $(TC_OBJ)
	@echo "Daemon compiled: $<"

$(PEEK_BIN): tools/telcom_peek.c include/telcom_kern_shared.h $(VERSION_H) | bin
	$(CLANG) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

build_tools: $(PEEK_BIN)
	@echo "Peek tool compiled: $<"

install: all
	@echo "Running install script..."
	@scripts/install.sh

package: all
	@echo "Building .deb package..."
	@scripts/build_package.sh

clean:
	rm -rf bpf/*.o bin telcom_*.deb
