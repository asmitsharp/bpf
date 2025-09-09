# Compile C code to eBPF bytecode
ebpf/packet_filter.o: ebpf/packet_filter.c
	clang -O2 -g -target bpf \
	      -I/usr/include \
	      -I/usr/include/asm-generic \
	      -I/usr/include/aarch64-linux-gnu \
	      -c $< -o $@

# Build Go program with embedded eBPF bytecode
build: ebpf/packet_filter.o
	go build -o packet-dropper .

# Clean compiled files
clean:
	rm -f ebpf/*.o packet-dropper

.PHONY: build clean