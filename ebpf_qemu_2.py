from bcc import BPF
from datetime import datetime
import os
import ctypes

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(proc_map, u32, u64);
BPF_PERF_OUTPUT(security_events);

struct event_data {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall[16];
};

static bool is_target_process() {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return proc_map.lookup(&pid) != NULL;
}

static void log_event(struct pt_regs *ctx, const char *syscall, const char *filename) {
    struct event_data data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 安全读取文件名
    if (filename) {
        bpf_probe_read_user_str(data.filename, sizeof(data.filename), filename);
    }
    
    // 直接使用静态字符串
    __builtin_memcpy(data.syscall, syscall, sizeof(data.syscall));
    
    security_events.perf_submit(ctx, &data, sizeof(data));
}

// 简化参数处理
int trace_execve(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    if (is_target_process()) {
        log_event(ctx, "execve", filename);
    }
    return 0;
}

int trace_setuid(struct pt_regs *ctx) {
    if (is_target_process()) {
        log_event(ctx, "setuid", NULL);
    }
    return 0;
}

int trace_capset(struct pt_regs *ctx) {
    if (is_target_process()) {
        log_event(ctx, "capset", NULL);
    }
    return 0;
}

int trace_openat(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    if (is_target_process()) {
        log_event(ctx, "openat", filename);
    }
    return 0;
}
"""

def detect_privilege_escalation(cpu, data, size):
    event = b["security_events"].event(data)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    sensitive_files = {
        b"/etc/passwd", b"/etc/shadow", 
        b"/root/.ssh/", b"/dev/mem"
    }
    
    alert = False
    reason = ""
    
    if event.syscall == b'execve':
        if b'sudo' in event.filename or b'su' in event.filename:
            reason = "特权命令执行"
            alert = True
    elif event.syscall == b'setuid':
        if event.uid == 0:
            reason = "尝试获取root权限"
            alert = True
    elif event.syscall == b'capset':
        reason = "修改进程能力"
        alert = True
    elif event.syscall == b'openat':
        for f in sensitive_files:
            if f in event.filename:
                reason = f"访问敏感文件: {event.filename.decode(errors='replace')}"
                alert = True
                break
    
    if alert:
        print(f"[!] 告警 ({timestamp})")
        print(f"    PID: {event.pid:<6} UID: {event.uid}")
        print(f"    进程: {event.comm.decode()}")
        print(f"    系统调用: {event.syscall.decode()}")
        if event.filename[0] != 0:
            print(f"    文件: {event.filename.decode(errors='replace')}")
        print(f"    原因: {reason}\\n")

# 初始化BPF
b = BPF(text=bpf_code, cflags=["-Wno-macro-redefined"])

# 5.15内核实际函数名验证
kprobes = {
    "execve": "do_sys_open",     # 实际跟踪execve的入口点
    "setuid": "__x64_sys_setuid",
    "capset": "__x64_sys_capset",
    "openat": "__x64_sys_openat"
}

for syscall, entry in kprobes.items():
    try:
        b.attach_kprobe(event=entry, fn_name=f"trace_{syscall}")
        print(f"成功挂载: {entry}")
    except Exception as e:
        print(f"挂载失败 {entry}: {str(e)}")

# 监控QEMU进程
print("启动监控...")
for line in os.popen("pgrep -f qemu-system"):
    pid = int(line.strip())
    c_pid = ctypes.c_uint(pid)
    b["proc_map"][c_pid] = ctypes.c_ulonglong(1)
    print(f"监控目标: PID {pid}")

try:
    b["security_events"].open_perf_buffer(detect_privilege_escalation)
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\\n监控结束")
