package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const bpfProgram = `
#include "common.h"
#include <linux/limits.h>

struct event {
    u32 pid;
    u64 nproc_cur;
    u64 nproc_max;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

SEC("kprobe/prlimit64")
int trace_prlimit(struct pt_regs *ctx) {
    struct event e = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get process name
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    
    // Check if it's MySQL
    if (bpf_strncmp(e.comm, sizeof(e.comm), "mysqld", 6) != 0) {
        return 0;
    }

    // Get resource limit type (arg2)
    unsigned int resource = (unsigned int)PT_REGS_PARM2(ctx);
    if (resource != RLIMIT_NPROC) {
        return 0;
    }

    struct rlimit *new_rlim = (struct rlimit *)PT_REGS_PARM3(ctx);
    if (new_rlim != NULL) {
        bpf_probe_read(&e.nproc_cur, sizeof(e.nproc_cur), &new_rlim->rlim_cur);
        bpf_probe_read(&e.nproc_max, sizeof(e.nproc_max), &new_rlim->rlim_max);
        e.pid = pid;
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    }
    
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

	kp, err := link.Kprobe("prlimit64", coll.Programs["trace_prlimit"], nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	// Create a perf reader
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			var event struct {
				PID      uint32
				NProcCur uint64
				NProcMax uint64
				Comm     [16]byte
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			log.Printf("MySQL(PID: %d) NPROC limits - current: %d, max: %d\n",
				event.PID, event.NProcCur, event.NProcMax)
		}
	}()

	fmt.Println("eBPF program attached. Press Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Exiting...")
}
