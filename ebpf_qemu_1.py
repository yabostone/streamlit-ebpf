from bcc import BPF
from datetime import datetime
import os
import ctypes

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/capability.h>

BPF_HASH(proc_map, u32, u64);
BPF_PERF_OUTPUT(security_events);

struct event_data {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall[32];
};

static bool is_target_process() {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return proc_map.lookup(&pid) != NULL;
}

static void log_event(struct pt_regs *ctx, const char *syscall, const char *filename) {
    struct event_data data = {};
    
    // 安全获取进程上下文
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 安全读取用户空间字符串
    if (filename) {
        bpf_probe_read_user_str(data.filename, sizeof(data.filename), filename);
    }
    
    // 记录系统调用名称
    const char *prefix = "sys_";
    char syscall_name[32] = {0};
    bpf_probe_read_kernel_str(syscall_name, sizeof(syscall_name), prefix);
    bpf_probe_read_kernel_str(syscall_name + 4, sizeof(syscall_name)-4, syscall);
    __builtin_memcpy(data.syscall, syscall_name, sizeof(data.syscall));

    security_events.perf_submit(ctx, &data, sizeof(data));
}

// 系统调用处理函数（适配5.15内核）
int sys_execve(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    if (is_target_process()) {
        log_event(ctx, "execve", filename);
    }
    return 0;
}

int sys_setuid(struct pt_regs *ctx) {
    if (is_target_process()) {
        log_event(ctx, "setuid", NULL);
    }
    return 0;
}

int sys_capset(struct pt_regs *ctx) {
    if (is_target_process()) {
        log_event(ctx, "capset", NULL);
    }
    return 0;
}

int sys_openat(struct pt_regs *ctx) {
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
    
    sensitive_patterns = [
        b"/etc/shadow", b"/etc/sudoers", 
        b"/root/.ssh/", b"/dev/mem"
    ]
    
    alert = False
    reason = ""
    
    # 检测逻辑
    if event.syscall.startswith(b'sys_execve'):
        if b'sudo' in event.filename or b'su' in event.filename:
            reason = "尝试执行特权命令"
            alert = True
    elif event.syscall.startswith(b'sys_setuid'):
        if event.uid == 0:
            reason = "尝试获取root权限"
            alert = True
    elif event.syscall.startswith(b'sys_capset'):
        reason = "尝试修改进程能力"
        alert = True
    elif event.syscall.startswith(b'sys_openat'):
        for pattern in sensitive_patterns:
            if pattern in event.filename:
                reason = f"访问敏感文件: {event.filename.decode(errors='ignore')}"
                alert = True
                break
    
    if alert:
        print(f"[!] 安全告警 ({timestamp})")
        print(f"    PID: {event.pid}  UID: {event.uid}")
        print(f"    进程: {event.comm.decode()}")
        print(f"    操作: {event.syscall.decode()}")
        if len(event.filename) > 0:
            print(f"    文件: {event.filename.decode(errors='replace')}")
        print(f"    风险: {reason}\\n")

# 初始化BPF
b = BPF(text=bpf_code, cflags=["-Wno-macro-redefined"])

# 手动适配5.15内核系统调用入口点
syscall_table = {
    "execve": "sys_execve",
    "setuid": "sys_setuid",
    "capset": "sys_capset",
    "openat": "sys_openat"
}

for name, entry in syscall_table.items():
    try:
        b.attach_kprobe(event=entry, fn_name=f"sys_{name}")
        print(f"成功挂载: {entry}")
    except Exception as e:
        print(f"挂载失败 {entry}: {str(e)}")

# 跟踪QEMU进程
def track_qemu():
    pids = []
    # 查找所有QEMU相关进程
    for line in os.popen("ps aux | grep 'qemu-system' | grep -v grep"):
        parts = line.split()
        if len(parts) >= 2:
            pid = int(parts[1])
            pids.append(pid)
            print(f"监控目标加入: PID {pid}")
    return pids

# 主监控循环
print("启动QEMU提权监控...")
track_qemu()

try:
    b["security_events"].open_perf_buffer(detect_privilege_escalation)
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\\n监控已停止")
