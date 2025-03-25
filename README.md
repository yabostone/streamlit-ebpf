确保内核大于4.19。
安装init.sh 中的基础包。
进行测试。

```
# 监控 open 系统调用（实时显示进程和文件名）
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s %s\n", comm, str(args->filename)); }'

# 统计系统调用数量（Ctrl+C 退出后显示摘要）
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
```
测试代码
