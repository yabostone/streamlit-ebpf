from bcc import BPF
from time import sleep
from platform import uname

# 根据内核版本调整代码
kernel_version = int(uname().release.split('.')[0])
bpf_code = """
#include <uapi/linux/ptrace.h>

BPF_HASH(retransmit_count, u32, u64);

int kprobe_tcp_retransmit(struct pt_regs *ctx %s) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u64 *count = retransmit_count.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        retransmit_count.update(&pid, &init_val);
    }
    return 0;
}
""" % (", struct sock *sk" if kernel_version <5 else "")

b = BPF(text=bpf_code)
# 确认内核中的函数名称（部分旧内核可能使用不同的名称）
try:
    b.attach_kprobe(event="tcp_retransmit_skb", fn_name="kprobe_tcp_retransmit")
except Exception as e:
    print("Detected kernel version specific issue, trying alternative...")
    b.attach_kprobe(event="tcp_retransmit", fn_name="kprobe_tcp_retransmit")

print("Tracing TCP retransmits... Ctrl+C to exit")

try:
    while True:
        sleep(1)
        for pid, count in b["retransmit_count"].items():
            print(f"PID {pid.value:<6}: {count.value:<4} retransmits")
        print("------------------------")
        b["retransmit_count"].clear()
except KeyboardInterrupt:
    print("Exiting...")
