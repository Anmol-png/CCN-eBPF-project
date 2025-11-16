# eBPF-Based System Activity & Energy Estimation Monitor

This project uses eBPF (extended Berkeley Packet Filter) to monitor low-level system events directly from the Linux kernel. The Python user-space program reads these kernel metrics, computes rates such as system calls per second, context switches, and packet counts, and then estimates energy usage based on an empirical model. All results are logged both in real time and into a CSV file.

---

## Features

- Kernel-level monitoring using eBPF tracepoints:
  - System calls (`raw_syscalls:sys_enter`)
  - Context switches (`sched:sched_switch`)
  - Network packets (`netif_receive_skb`)
- Real-time CPU usage measurement (via `psutil`)
- Energy consumption estimation using a custom formula
- Continuous logging to `system_monitor_log.csv`
- Dynamic monitoring:
  - Adjusts process niceness on high energy
  - Slows sampling rate on high CPU
- Running average of system calls per second
- Low-overhead and safe thanks to eBPF’s verified execution model

---

##  How It Works

### **1. Kernel-Side (eBPF Program)**  
The eBPF program attaches to kernel tracepoints.  
Each tracepoint triggers whenever a corresponding system event occurs:

- **System call** → increments `sys_cnt` map  
- **Context switch** → increments `ctx_cnt` map  
- **Incoming packet** → increments `pkt_cnt` map  

These counters are stored in **eBPF hash maps located in kernel memory**, making updates extremely fast and efficient.

### **2. User-Space (Python Program)**  
The Python script interacts with the kernel using the BCC framework:

1. Loads eBPF program into the kernel
2. Periodically reads the counters from the kernel maps
3. Computes:
   - Event deltas (events per second)
   - CPU usage
   - Running averages
   - Estimated energy consumption
4. Logs everything into a CSV file
5. Prints human-readable live metrics on the terminal

### **3. Adaptive Logic**
To avoid system overload:
- If **energy > 8 J**, the monitor reduces its priority (`renice`)
- If **CPU > 80%**, sampling speed is decreased

---

## 📦 Requirements

## Requirements

### Supported OS
- Linux kernel **5.4+** (eBPF and tracepoint support required)

### Required Packages
Install BCC and kernel headers:
sudo apt install bpfcc-tools linux-headers-$(uname -r)

### Python Version
- Python **3.8+**

### Python Dependencies
pip install psutil




  
