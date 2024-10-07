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
