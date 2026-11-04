#!/usr/bin/env bash
# Diagnostic for #440, not meant to be merged. It always exits 0: the printed
# counts are the result, and the DIAG, diag440cpu, and diag440subset lines are
# what to read.
set -uo pipefail

bin=$1
cd cmd/tinytap || exit 1
out=$(mktemp)
T=/sys/kernel/tracing
ops=2000
cpus=$(nproc)

run() { sudo "$bin" -test.v "$@" >"$out" 2>&1; }

# dd issues exactly ${ops} reads and ${ops} writes, with no tinytap loaded.
dd_cmd() { echo "taskset -c $1 dd if=/dev/zero of=/dev/null bs=1 count=${ops} status=none"; }

echo "==> ftrace, no tinytap loaded (expect ${ops} of each)"
sudo sh -c "echo 1 >${T}/events/syscalls/sys_enter_write/enable; echo 1 >${T}/events/syscalls/sys_enter_read/enable"
for round in 1 2 3 4 5; do
    for cpu in $(seq 0 $((cpus - 1))); do
        sudo sh -c "echo 0 >${T}/tracing_on; echo >${T}/trace; echo >${T}/set_event_pid"
        sudo sh -c "echo \$\$ >${T}/set_event_pid; echo 1 >${T}/tracing_on; exec $(dd_cmd "$cpu")"
        sudo sh -c "echo 0 >${T}/tracing_on; cat ${T}/trace" >"$out"
        echo "DIAG ftrace round=${round} cpu=${cpu} write=$(grep -c 'sys_write(' "$out") read=$(grep -c 'sys_read(' "$out")"
    done
done
sudo sh -c "echo 0 >${T}/events/syscalls/sys_enter_write/enable; echo 0 >${T}/events/syscalls/sys_enter_read/enable; echo >${T}/set_event_pid; echo >${T}/trace; echo 1 >${T}/tracing_on"

echo "==> bpftrace, no tinytap loaded (expect ${ops} of each)"
if command -v bpftrace >/dev/null; then
    prog='BEGIN { printf("ready\n"); }
tracepoint:syscalls:sys_enter_write /comm == "dd"/ { @write = count(); }
tracepoint:syscalls:sys_enter_read /comm == "dd"/ { @read = count(); }'
    for round in 1 2 3 4 5; do
        for cpu in $(seq 0 $((cpus - 1))); do
            sudo bpftrace -e "$prog" >"$out" 2>&1 &
            job=$!
            for _ in $(seq 150); do
                grep -q ready "$out" && break
                sleep 0.1
            done
            # shellcheck disable=SC2046
            $(dd_cmd "$cpu")
            sudo pkill -INT -x bpftrace
            wait "$job"
            echo "DIAG bpftrace round=${round} cpu=${cpu} write=$(sed -n 's/^@write: //p' "$out") read=$(sed -n 's/^@read: //p' "$out")"
        done
    done
else
    echo "DIAG bpftrace unavailable"
fi

echo "==> per-CPU, through the loader"
for i in 1 2 3; do
    run -test.run '^TestDiag440_PerCPU$'
    grep 'diag440cpu' "$out" | sed -E "s/^ *[^ ]+ /cpurun${i} /"
done

echo "==> attach subsets, without the loader"
for i in 1 2 3; do
    run -test.run '^TestDiag440_AttachSubset$'
    grep 'diag440subset' "$out" | sed -E "s/^ *[^ ]+ /subrun${i} /"
done

exit 0
