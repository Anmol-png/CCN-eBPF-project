#!/usr/bin/env python3
# full_ebpf_monitor.py
from bcc import BPF
import psutil, time, datetime, os, csv

# ----------------- eBPF Program -----------------
bpf_text = r"""
BPF_HASH(sys_cnt, u32, u64);
BPF_HASH(ctx_cnt, u32, u64);
BPF_HASH(pkt_cnt, u32, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 key = 0;
    u64 one = 1;
    u64 *val = sys_cnt.lookup(&key);
    if (val) { (*val) += 1; } else { sys_cnt.update(&key, &one); }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 key = 0;
    u64 one = 1;
    u64 *val = ctx_cnt.lookup(&key);
    if (val) { (*val) += 1; } else { ctx_cnt.update(&key, &one); }
    return 0;
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    u32 key = 0;
    u64 one = 1;
    u64 *val = pkt_cnt.lookup(&key);
    if (val) { (*val) += 1; } else { pkt_cnt.update(&key, &one); }
    return 0;
}
"""

b = BPF(text=bpf_text)

# ----------------- Helper Functions -----------------
def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def read_map_counter(table, default=0):
    try:
        keys = list(table.keys())
        if not keys: return default
        return int(table[keys[0]].value)
    except Exception:
        return default

def get_syscalls(prev_sys):
    table = b["sys_cnt"]
    total = read_map_counter(table, default=0)
    delta = total - prev_sys if prev_sys is not None else 0
    return total, delta

def get_context_switches(prev_ctx):
    table = b["ctx_cnt"]
    total = read_map_counter(table, default=0)
    delta = total - prev_ctx if prev_ctx is not None else 0
    return total, delta

def get_total_packets(prev_pkt):
    table = b["pkt_cnt"]
    total = read_map_counter(table, default=0)
    delta = total - prev_pkt if prev_pkt is not None else 0
    return total, delta

def estimate_energy(cpu, syscalls_s, ctx_s):
    return round((cpu * 0.4) + (syscalls_s * 0.00005) + (ctx_s * 0.0002), 2)

# ----------------- CSV Setup -----------------
log_file = "system_monitor_log.csv"
with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp", "cpu_percent", "packets", "delta_packets",
        "syscalls_total", "syscalls_per_s", "ctx_total", "ctx_per_s",
        "energy_estimate", "syscalls_avg"   # <-- NEW column
    ])

print("Logging to:", log_file)
print("Press Ctrl+C to stop\n")

# ----------------- Initialize previous counters -----------------
time.sleep(0.5)
prev_sys_total = read_map_counter(b["sys_cnt"], default=0)
prev_ctx_total = read_map_counter(b["ctx_cnt"], default=0)
prev_pkt_total = read_map_counter(b["pkt_cnt"], default=0)

# ---------- running history for average calculation
syscalls_history = []

try:
    while True:
        cpu = get_cpu_usage()
        sys_total, sys_delta = get_syscalls(prev_sys_total)
        ctx_total, ctx_delta = get_context_switches(prev_ctx_total)
        pkt_total, pkt_delta = get_total_packets(prev_pkt_total)

        # ---------- Update running history & average
        syscalls_history.append(sys_delta)
        syscalls_avg = round(sum(syscalls_history)/len(syscalls_history),2)

        energy = estimate_energy(cpu, sys_delta, ctx_delta)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Print without average
        print(f"[{timestamp}] CPU:{cpu:5.1f}% |Packets:{pkt_total:6} |Δpkts:{pkt_delta:<6} "
              f"|Syscalls/s:{sys_delta:<6} |CtxSwitch/s:{ctx_delta:<6} |Energy ≈{energy:6.2f}J "
              )

        # Write CSV
        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, cpu, pkt_total, pkt_delta,
                sys_total, sys_delta, ctx_total, ctx_delta,
                energy, syscalls_avg
            ])

        # Adaptive actions
        if energy > 8.0:
            print("High Energy Detected! Reducing system load...")
            os.system("renice +10 -p $(pgrep -f full_ebpf_monitor.py) >/dev/null 2>&1")
            time.sleep(3)
        elif cpu > 80:
            print("High CPU Usage! Slowing monitoring rate...")
            time.sleep(3)
        else:
            time.sleep(0.2)

        prev_sys_total = sys_total
        prev_ctx_total = ctx_total
        prev_pkt_total = pkt_total

except KeyboardInterrupt:
    print("\nMonitoring stopped by user.")
    print(f"Data saved in '{log_file}'")
    if syscalls_history:
        final_avg = round(sum(syscalls_history)/len(syscalls_history),2)
        print(f"Final Average Syscalls/s: {final_avg}")

