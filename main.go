package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const bpfProgram = `
#include <uapi/linux/ptrace.h>

SEC("kprobe/setrlimit")
int trace_setrlimit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("setrlimit called by PID: %d\\n", pid);
    return 0;
}
`

func main() {
	// Allow the current process to lock memory for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(bpfProgram))
	if err != nil {
		log.Fatalf("failed to load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create collection: %v", err)
	}
	defer coll.Close()

	kp, err := link.Kprobe("setrlimit", coll.Programs["trace_setrlimit"], nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	fmt.Println("eBPF program attached. Press Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Exiting...")
}
