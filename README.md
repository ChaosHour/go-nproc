# Go-NPROC

I wanted a way to monitory nproc usage for MySQL on Linux using Go and eBPF.

## Warning

This is a work in progress and not ready for production use. I am still learning Go and eBPF.
This is currently just a proof of concept and I am testing it.

## To Compile

```GO
go build -o go-nproc

FreeBSD:
env GOOS=freebsd GOARCH=amd64 go build .

On Mac:
env GOOS=darwin GOARCH=amd64 go build .

Linux:
env GOOS=linux GOARCH=amd64 go build .
```

## A note about Linux nproc, MySQL, and pthreads

Currently, I am using these methods to monitor nproc usage:

```bash
Testing:
Set the ulimit for nproc for the running mysql instance - settings will go back to defaults after a reboot:

prlimit --nproc=unlimited:unlimited --pid $(pidof mysqld)



Check the current limits for a running mysql instance:
cat /proc/`pidof mysqld`/limits | egrep "(processes|files)"

Max processes             unlimited            unlimited            processes
Max open files            150000               150000               files



Check nproc usage in realtime:
Term 1:
watch connections:
watch -n 3 "mysqladmin extended-status | grep -wi 'threads_connected\|threads_running' | awk '{ print \$2, \$4}'"



Term 2: 
nproc in realtime:
watch -n 3 'ps -o nlwp,pid,lwp,args -u mysql | sort -n'
```

## Install and verify

Here's a step-by-step guide to compile and test the eBPF program:

1. First, ensure you have the required dependencies:
```bash
# For Debian/Ubuntu
sudo apt-get install linux-headers-$(uname -r)
sudo apt-get install clang llvm

# For RHEL/CentOS
sudo yum install kernel-headers
sudo yum install clang llvm
```

2. Create a `common.h` file in the same directory:

### [common.h](file:///Users/klarsen/projects/go-nproc/common.h)
```c


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/resource.h>
```

3. Compile and run:
```bash
# Build the program
go build -o nproc-monitor

# Run it (requires root/sudo)
sudo ./nproc-monitor
```

4. Test it by running these commands in another terminal:
```bash
# Method 1: If you have MySQL running, try changing its ulimit
sudo prlimit --pid $(pidof mysqld) --nproc=2000:3000

# Method 2: If MySQL isn't running, simulate with a test process
bash -c 'exec -a mysqld sleep 1000' &
sudo prlimit --pid $! --nproc=2000:3000
```

You should see output like:
```bash
eBPF program attached. Press Ctrl+C to exit.
MySQL(PID: xxxx) NPROC limits - current: 2000, max: 3000
```

Common troubleshooting:
1. If you get permission errors, make sure you're running as root
2. If the program fails to load, check kernel version (`uname -r`) - needs 4.15+
3. If headers are missing, verify the kernel headers are properly installed
4. Use `dmesg` to check for any eBPF verification errors
