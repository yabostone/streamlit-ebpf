from bcc import BPF

# 定义 eBPF 程序
bpf_code = """
#include <uapi/linux/ptrace.h>

BPF_HASH(stats, u32);

int count_syscalls(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = stats.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        u64 init = 1;
        stats.update(&pid, &init);
    }
    return 0;
}
"""

# 加载 eBPF 程序
b = BPF(text=bpf_code)
b.attach_kprobe(event=b.get_syscall_fnname("open"), fn_name="count_syscalls")

# 输出统计
print("PID\tCOUNT")
while True:
    try:
        for k, v in b["stats"].items():
            print(f"{k.value}\t{v.value}")
        print("---")
        time.sleep(2)
    except KeyboardInterrupt:
        exit()
