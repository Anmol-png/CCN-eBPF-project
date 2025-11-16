#!/usr/bin/env python3
import psutil, time, datetime, csv, os

log_file = "baseline_monitor_log.csv"
interval = 1.0

# ---- Read eBPF Average Syscalls ----
EBPF_LOG = "system_monitor_log.csv"
INJECTED_SYSCALLS = 0

try:
    if os.path.exists(EBPF_LOG):
        with open(EBPF_LOG, "r") as f:
            reader = list(csv.reader(f))
            if len(reader) > 1:
                header = reader[0]
                last_line = reader[-1]
                if "syscalls_avg" in header:
                    idx = header.index("syscalls_avg")
                    INJECTED_SYSCALLS = float(last_line[idx])
except Exception as e:
    print("Could not read eBPF average syscalls, defaulting to 0:", e)
    INJECTED_SYSCALLS = 0

def read_ctxt():
    try:
        with open("/proc/stat", "r") as f:
            for line in f:
                if line.startswith("ctxt"):
                    return int(line.split()[1])
    except:
        return 0

if os.path.exists(log_file):
    os.remove(log_file)

with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp", "cpu_percent", "packets", "delta_packets",
        "syscalls_per_s", "ctxswitch_per_s", "energy_estimate"
    ])

print("Traditional CPU + Packet monitoring started...")
print(f"Logging to: {log_file}")
print(f"Using injected syscalls (eBPF avg): {INJECTED_SYSCALLS}")
print("Press Ctrl+C to stop\n")

prev_pkt = psutil.net_io_counters().packets_sent + psutil.net_io_counters().packets_recv
prev_ctxt = read_ctxt()

try:
    while True:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cpu = psutil.cpu_percent(interval=interval)

        net = psutil.net_io_counters()
        packets = net.packets_sent + net.packets_recv
        delta_pkt = packets - prev_pkt

        # Injected syscalls
        syscalls_s = INJECTED_SYSCALLS

        # Context switch rate
        cur_ctxt = read_ctxt()
        ctxswitch_s = max(cur_ctxt - prev_ctxt, 0)
        prev_ctxt = cur_ctxt

        # Energy estimate
        energy = round((cpu * 0.4) +
                       (syscalls_s * 0.00005) +
                       (ctxswitch_s * 0.0002), 2)

        print(f"[{ts}] CPU: {cpu:5.1f}% | Packets: {packets:<6} | Δpkts: {delta_pkt:<4} | "
              f"Syscalls:{syscalls_s:<7} | CtxSwitch: {ctxswitch_s:<5} | Energy ≈ {energy:6.2f} J")

        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([ts, cpu, packets, delta_pkt, syscalls_s, ctxswitch_s, energy])

        prev_pkt = packets

except KeyboardInterrupt:
    print("\nMonitoring stopped by user.")
    print(f"Data saved in '{log_file}'")

