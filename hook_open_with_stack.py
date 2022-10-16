import sys
import logging
from pathlib import Path
from datetime import datetime

from bcc import BPF

GLOBAL_LOGGERS = {}
logger = None # type: logging.Logger

def setup_logger(log_tag: str, log_path: Path, first_call: bool = False) -> logging.Logger:
    '''
    输出的信息太多 Terminal可能不全 记录到日志文件
    '''
    if log_path.parent.exists() is False:
        log_path.parent.mkdir()
    logger = GLOBAL_LOGGERS.get(log_tag)
    if logger:
        return logger

    logger = logging.getLogger(log_tag)
    GLOBAL_LOGGERS[log_tag] = logger

    # 避免重新载入脚本时重复输出
    if first_call and logger.hasHandlers():
        logger.handlers.clear()

    # 设置所有 handler 的日志等级
    logger.setLevel(logging.DEBUG)

    # 添加终端 handler 只打印原始信息
    formatter = logging.Formatter('%(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # 添加文件 handler 记录详细时间和内容
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    fh = logging.FileHandler(log_path.as_posix(), encoding='utf-8', delay=True)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger


BPF_CODE_include = """
#include <linux/ptrace.h>
"""

BPF_CODE_open = """
struct probe_open_data_t {
    u32 pid;
    u32 tid;
    u32 uid;
    char pathname[256];
    int flags;
};

BPF_PERCPU_ARRAY(open_data, struct probe_open_data_t, 1);
BPF_PERF_OUTPUT(perf_open);

// int open(const char* pathname, int flags, ...)

int probe_hook_open_enter(struct pt_regs *ctx) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u32 uid = bpf_get_current_uid_gid();

        PID_FILTER
        TID_FILTER
        UID_FILTER

        u32 zero = 0;
        struct probe_open_data_t *data = open_data.lookup(&zero);
        if (!data)
            return 0;

        data->pid = pid;
        data->tid = tid;
        data->uid = uid;
        data->flags = PT_REGS_PARM2(ctx);

        int ret = bpf_probe_read_user(data->pathname, sizeof(data->pathname), (void *)PT_REGS_PARM1(ctx));
        perf_open.perf_submit(ctx, data, sizeof(struct probe_open_data_t));
        return 0;
}
"""

class BPFHooker:

    def __init__(self, library: str, uid: int, pid: int = -1, tid: int = -1) -> None:
        # 可以是库名 比如 libssl.so 取 ssl
        # 可以是是目标ELF程序的完整路径 比如 /apex/com.android.conscrypt/lib64/libssl.so
        # 如果要写路径 那么内存里面是什么就是什么 不要使用软链接的路径
        self.uid = uid
        self.pid = pid
        self.tid = tid
        self.library = library
        self.bpf_module = None # type: BPF

    def hook(self):
        text = BPF_CODE_include
        text += BPF_CODE_open
        if self.pid > 0:
            text = text.replace('PID_FILTER', f'if (pid != {self.pid}) {{ return 0; }}')
        else:
            text = text.replace('PID_FILTER', '')
        if self.tid > 0:
            text = text.replace('TID_FILTER', f'if (tid != {self.tid}) {{ return 0; }}')
        else:
            text = text.replace('TID_FILTER', '')
        if self.uid > 0:
            text = text.replace('UID_FILTER', f'if (uid != {self.uid}) {{ return 0; }}')
        else:
            text = text.replace('UID_FILTER', '')
        self.bpf_module = BPF(text=text)
        self.bpf_module.attach_uprobe(name=self.library, sym='open', fn_name='probe_hook_open_enter', pid=self.pid)
        logger.info('attach end')

    def print_event_perf_open(self, ctx, data, size):
        event = self.bpf_module['perf_open'].event(data)
        logger.info(f'[open] {event.pathname.decode("utf-8")}')

    def show(self):
        self.bpf_module["perf_open"].open_perf_buffer(self.print_event_perf_open, unwind_call_stack=1)
        while True:
            try:
                self.bpf_module.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

def main():
    global logger
    log_tag = 'open'
    log_time = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_path = Path(__file__).parent / f'logs/{log_tag}_{log_time}.log'
    logger = setup_logger(log_tag, log_path, first_call=True)
    uid = 10235
    library = "/apex/com.android.runtime/lib64/bionic/libc.so"
    bpf_hooker = BPFHooker(library, uid)
    bpf_hooker.hook()
    bpf_hooker.show()


if __name__ == '__main__':
    main()