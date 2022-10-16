
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/logging.h>

#if defined(USE_BIONIC_UAPI_HEADERS)
#include <uapi/linux/perf_event.h>
#include <uapi/asm-arm/asm/perf_regs.h>
#include <uapi/asm-x86/asm/perf_regs.h>
#define perf_event_arm_regs perf_event_arm64_regs
#include <uapi/asm-arm64/asm/perf_regs.h>
#else
#include <linux/perf_event.h>
#include <asm-arm/asm/perf_regs.h>
#include <asm-x86/asm/perf_regs.h>
#define perf_event_arm_regs perf_event_arm64_regs
#include <asm-arm64/asm/perf_regs.h>
#endif

#include <unwindstack/Unwinder.h>
#include <unwindstack/MachineArm.h>
#include <unwindstack/MachineArm64.h>
#include <unwindstack/MachineX86.h>
#include <unwindstack/MachineX86_64.h>
#include <unwindstack/Maps.h>
#include <unwindstack/RegsArm.h>
#include <unwindstack/RegsArm64.h>
#include <unwindstack/RegsX86.h>
#include <unwindstack/RegsX86_64.h>
#include <unwindstack/UserArm.h>
#include <unwindstack/UserArm64.h>
#include <unwindstack/UserX86.h>
#include <unwindstack/UserX86_64.h>
#include <unwindstack/Maps.h>

namespace unwinddaemon {

struct UserRegs {
    uint64_t abi;
    uint64_t regs[33];
};

struct UserStack {
    uint64_t size;
    char data[16384];
    uint64_t dyn_size;
};

struct DataBuff {
    UserRegs user_regs;
    UserStack user_stack;
};

enum ArchType {
  ARCH_X86_32,
  ARCH_X86_64,
  ARCH_ARM,
  ARCH_ARM64,
  ARCH_UNSUPPORTED,
};

class ScopedCurrentArch {
 public:
  explicit ScopedCurrentArch(ArchType arch) : saved_arch(current_arch) {
    current_arch = arch;
  }
  ~ScopedCurrentArch() {
    current_arch = saved_arch;
  }
  static ArchType GetCurrentArch() { return current_arch; }

 private:
  ArchType saved_arch;
  static ArchType current_arch;
};

ArchType ScopedCurrentArch::current_arch = ARCH_ARM64;

struct RegSet {
  ArchType arch;
  uint64_t valid_mask;
  uint64_t data[64];

  RegSet(int abi, uint64_t valid_mask, const uint64_t* valid_regs);

  bool GetRegValue(size_t regno, uint64_t* value) const;
  bool GetSpRegValue(uint64_t* value) const;
};

ArchType GetArchForAbi(ArchType machine_arch, int abi) {
  if (abi == PERF_SAMPLE_REGS_ABI_32) {
    if (machine_arch == ARCH_X86_64) {
      return ARCH_X86_32;
    }
    if (machine_arch == ARCH_ARM64) {
      return ARCH_ARM;
    }
  } else if (abi == PERF_SAMPLE_REGS_ABI_64) {
    if (machine_arch == ARCH_X86_32) {
      return ARCH_X86_64;
    }
    if (machine_arch == ARCH_ARM) {
      return ARCH_ARM64;
    }
  }
  return machine_arch;
}

RegSet::RegSet(int abi, uint64_t valid_mask, const uint64_t* valid_regs) : valid_mask(valid_mask) {
  arch = GetArchForAbi(ScopedCurrentArch::GetCurrentArch(), abi);
  memset(data, 0, sizeof(data));
  for (int i = 0, j = 0; i < 64; ++i) {
    if ((valid_mask >> i) & 1) {
      data[i] = valid_regs[j++];
    }
  }
  if (ScopedCurrentArch::GetCurrentArch() == ARCH_ARM64 && abi == PERF_SAMPLE_REGS_ABI_32) {
    // The kernel dumps arm64 regs, but we need arm regs. So map arm64 regs into arm regs.
    data[PERF_REG_ARM_PC] = data[PERF_REG_ARM64_PC];
  }
}

bool RegSet::GetRegValue(size_t regno, uint64_t* value) const {
  CHECK_LT(regno, 64U);
  LOG(DEBUG) << "GetRegValue valid_mask:" << valid_mask << " regno:" << regno;
  if ((valid_mask >> regno) & 1) {
    *value = data[regno];
    return true;
  }
  return false;
}

bool RegSet::GetSpRegValue(uint64_t* value) const {
  size_t regno;
  switch (arch) {
    case ARCH_X86_32:
      regno = PERF_REG_X86_SP;
      break;
    case ARCH_X86_64:
      regno = PERF_REG_X86_SP;
      break;
    case ARCH_ARM:
      regno = PERF_REG_ARM_SP;
      break;
    case ARCH_ARM64:
      regno = PERF_REG_ARM64_SP;
      break;
    default:
      return false;
  }
  return GetRegValue(regno, value);
}

std::string DumpFrames(const unwindstack::Unwinder& unwinder) {
  std::string str;
  for (size_t i = 0; i < unwinder.NumFrames(); i++) {
    str += unwinder.FormatFrame(i) + "\n";
  }
  return str;
}

unwindstack::Regs* GetBacktraceRegs(const RegSet& regs) {
  switch (regs.arch) {
    case ARCH_ARM: {
      unwindstack::arm_user_regs arm_user_regs;
      memset(&arm_user_regs, 0, sizeof(arm_user_regs));
      static_assert(static_cast<int>(unwindstack::ARM_REG_R0) == static_cast<int>(PERF_REG_ARM_R0),
                    "");
      static_assert(
          static_cast<int>(unwindstack::ARM_REG_LAST) == static_cast<int>(PERF_REG_ARM_MAX), "");
      for (size_t i = unwindstack::ARM_REG_R0; i < unwindstack::ARM_REG_LAST; ++i) {
        arm_user_regs.regs[i] = static_cast<uint32_t>(regs.data[i]);
      }
      return unwindstack::RegsArm::Read(&arm_user_regs);
    }
    case ARCH_ARM64: {
      unwindstack::arm64_user_regs arm64_user_regs;
      memset(&arm64_user_regs, 0, sizeof(arm64_user_regs));
      static_assert(
          static_cast<int>(unwindstack::ARM64_REG_R0) == static_cast<int>(PERF_REG_ARM64_X0), "");
      static_assert(
          static_cast<int>(unwindstack::ARM64_REG_R30) == static_cast<int>(PERF_REG_ARM64_LR), "");
      memcpy(&arm64_user_regs.regs[unwindstack::ARM64_REG_R0], &regs.data[PERF_REG_ARM64_X0],
             sizeof(uint64_t) * (PERF_REG_ARM64_LR - PERF_REG_ARM64_X0 + 1));
      arm64_user_regs.sp = regs.data[PERF_REG_ARM64_SP];
      arm64_user_regs.pc = regs.data[PERF_REG_ARM64_PC];
      auto regs =
          static_cast<unwindstack::RegsArm64*>(unwindstack::RegsArm64::Read(&arm64_user_regs));
      uint64_t arm64_pac_mask_ = 0;
      regs->SetPACMask(arm64_pac_mask_);
      return regs;
    }
    case ARCH_X86_32: {
      unwindstack::x86_user_regs x86_user_regs;
      memset(&x86_user_regs, 0, sizeof(x86_user_regs));
      x86_user_regs.eax = static_cast<uint32_t>(regs.data[PERF_REG_X86_AX]);
      x86_user_regs.ebx = static_cast<uint32_t>(regs.data[PERF_REG_X86_BX]);
      x86_user_regs.ecx = static_cast<uint32_t>(regs.data[PERF_REG_X86_CX]);
      x86_user_regs.edx = static_cast<uint32_t>(regs.data[PERF_REG_X86_DX]);
      x86_user_regs.ebp = static_cast<uint32_t>(regs.data[PERF_REG_X86_BP]);
      x86_user_regs.edi = static_cast<uint32_t>(regs.data[PERF_REG_X86_DI]);
      x86_user_regs.esi = static_cast<uint32_t>(regs.data[PERF_REG_X86_SI]);
      x86_user_regs.esp = static_cast<uint32_t>(regs.data[PERF_REG_X86_SP]);
      x86_user_regs.eip = static_cast<uint32_t>(regs.data[PERF_REG_X86_IP]);
      return unwindstack::RegsX86::Read(&x86_user_regs);
    }
    case ARCH_X86_64: {
      unwindstack::x86_64_user_regs x86_64_user_regs;
      memset(&x86_64_user_regs, 0, sizeof(x86_64_user_regs));
      x86_64_user_regs.rax = regs.data[PERF_REG_X86_AX];
      x86_64_user_regs.rbx = regs.data[PERF_REG_X86_BX];
      x86_64_user_regs.rcx = regs.data[PERF_REG_X86_CX];
      x86_64_user_regs.rdx = regs.data[PERF_REG_X86_DX];
      x86_64_user_regs.r8 = regs.data[PERF_REG_X86_R8];
      x86_64_user_regs.r9 = regs.data[PERF_REG_X86_R9];
      x86_64_user_regs.r10 = regs.data[PERF_REG_X86_R10];
      x86_64_user_regs.r11 = regs.data[PERF_REG_X86_R11];
      x86_64_user_regs.r12 = regs.data[PERF_REG_X86_R12];
      x86_64_user_regs.r13 = regs.data[PERF_REG_X86_R13];
      x86_64_user_regs.r14 = regs.data[PERF_REG_X86_R14];
      x86_64_user_regs.r15 = regs.data[PERF_REG_X86_R15];
      x86_64_user_regs.rdi = regs.data[PERF_REG_X86_DI];
      x86_64_user_regs.rsi = regs.data[PERF_REG_X86_SI];
      x86_64_user_regs.rbp = regs.data[PERF_REG_X86_BP];
      x86_64_user_regs.rsp = regs.data[PERF_REG_X86_SP];
      x86_64_user_regs.rip = regs.data[PERF_REG_X86_IP];
      return unwindstack::RegsX86_64::Read(&x86_64_user_regs);
    }
    default:
      return nullptr;
  }
}

bool UnwindCallChain(int pid, uint64_t reg_mask, DataBuff *data_buf, int client_sockfd) {
    RegSet regs(data_buf->user_regs.abi, reg_mask, data_buf->user_regs.regs);
    LOG(DEBUG) << "abi:" << data_buf->user_regs.abi << ", arch:" << regs.arch;

    uint64_t sp_reg_value;
    if (!regs.GetSpRegValue(&sp_reg_value)) {
        std::cerr << "can't get sp reg value";
        return false;
    }
    LOG(DEBUG) << "sp_reg_value: 0x" << std::hex << sp_reg_value;
    
    uint64_t stack_addr = sp_reg_value;
    const char *stack = data_buf->user_stack.data;
    size_t stack_size = data_buf->user_stack.dyn_size;
    
    std::unique_ptr<unwindstack::Regs> unwind_regs(GetBacktraceRegs(regs));
    if (!unwind_regs) {
      return false;
    }
    std::shared_ptr<unwindstack::Memory> stack_memory = unwindstack::Memory::CreateOfflineMemory(
        reinterpret_cast<const uint8_t*>(stack), stack_addr, stack_addr + stack_size
    );

    std::string map_buffer;
    std::unique_ptr<unwindstack::Maps> maps;
    std::string proc_map_file = "/proc/" + std::to_string(pid) + "/maps";
    android::base::ReadFileToString(proc_map_file, &map_buffer);
    maps.reset(new unwindstack::BufferMaps(map_buffer.c_str()));
    maps->Parse();
    unwindstack::Unwinder unwinder(512, maps.get(), unwind_regs.get(), stack_memory);
    // default is true
    // unwinder.SetResolveNames(false);
    unwinder.Unwind();
    std::string frame_info = DumpFrames(unwinder);
    // LOG(DEBUG) << "frame_info:" << frame_info;
    int len = frame_info.length();
    send(client_sockfd, &len, 4, 0);
    send(client_sockfd, frame_info.c_str(), len, 0);
    return true;
}
}

static std::map<std::string, android::base::LogSeverity> log_severity_map = {
    {"verbose", android::base::VERBOSE}, {"debug", android::base::DEBUG},
    {"info", android::base::INFO},       {"warning", android::base::WARNING},
    {"error", android::base::ERROR},     {"fatal", android::base::FATAL},
};

bool GetLogSeverity(const std::string& name, android::base::LogSeverity* severity) {
  auto it = log_severity_map.find(name);
  if (it != log_severity_map.end()) {
    *severity = it->second;
    return true;
  }
  return false;
}

static void StderrLogger(android::base::LogId, android::base::LogSeverity severity, const char*,
                         const char* file, unsigned int line, const char* message) {
  static const char log_characters[] = "VDIWEFF";
  char severity_char = log_characters[severity];
  fprintf(stderr, "%c %s:%u] %s\n", severity_char, file, line, message);
}

int main(int argc, char** argv) {

  android::base::InitLogging(argv, StderrLogger);
  android::base::LogSeverity log_severity = android::base::DEBUG;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--log") == 0) {
      if (i + 1 < argc) {
        ++i;
        if (!GetLogSeverity(argv[i], &log_severity)) {
          LOG(ERROR) << "Unknown log severity: " << argv[i];
          return 1;
        }
      } else {
        LOG(WARNING) << "Missing argument for --log option.\n";
      }
    }
  }
  android::base::ScopedLogSeverity severity(log_severity);

  int server_sockfd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (server_sockfd < 0) {
    LOG(DEBUG) << "create server socket failed";
    return 1;
  }
  LOG(DEBUG) << "create server socket end, server_sockfd=" << server_sockfd;

  struct sockaddr_un mysock_addr;
  mysock_addr.sun_family = PF_UNIX;
  strcpy(mysock_addr.sun_path, "/dev/socket/mysock");
  unlink(mysock_addr.sun_path);

  int len = strlen(mysock_addr.sun_path) + sizeof(mysock_addr.sun_family);
  int bind_status = bind(server_sockfd, (struct sockaddr *)&mysock_addr, len);
  if (bind_status < 0) {
    LOG(DEBUG) << "bind server failed, path=" << mysock_addr.sun_path;
    return 1;
  }

  int listen_status = listen(server_sockfd, 5);
  if (listen_status < 0) {
    LOG(DEBUG) << "listen failed";
    return 1;
  }

  int client_sockfd;
  struct sockaddr_un remote_addr;
  socklen_t remote_addr_len;
  while (true) {
    client_sockfd = accept(server_sockfd, (struct sockaddr *)&remote_addr, &remote_addr_len);
    if(client_sockfd < 0) {
      break;
    };
    LOG(DEBUG) << "accept fd:" << client_sockfd;

    // recv 4 byte pid
    uint8_t pid_buffer[4];
    int recv_len = recv(client_sockfd, &pid_buffer, 4, 0);
    if (recv_len != 4) {
      LOG(DEBUG) << "read pid failed, recv_len=" << recv_len;
      break;
    }
    int pid = *(int *)pid_buffer;
    LOG(DEBUG) << "read pid:" << pid;

    // recv 4 byte size
    uint8_t size_buffer[4];
    recv_len = recv(client_sockfd, &size_buffer, 4, 0);
    if (recv_len != 4) {
      LOG(DEBUG) << "read size failed, recv_len=" << recv_len;
      break;
    }
    int size = *(int *)size_buffer;
    LOG(DEBUG) << "read size:" << size;

    // max size 32k
    uint8_t full_buffer[1024 * 32];
    uint8_t tmp_buffer[1024];
    int total_len = 0;

    while (true) {
      recv_len = recv(client_sockfd, &tmp_buffer, 1024, 0);
      memcpy(full_buffer + total_len, tmp_buffer, recv_len);
      if (recv_len > 0) {
        total_len += recv_len;
      } else {
        break;
      }
      if (total_len >= size) {
        break;
      }
    }
    if (size != total_len) {
      LOG(DEBUG) << "size:" << size <<" not equal total_len:" << total_len;
    }

    LOG(DEBUG) << "recv DataBuff total_len:" << total_len;
    if (total_len > 0) {
      uint64_t reg_mask = ((1ULL << 33) - 1);
      unwinddaemon::DataBuff* data_buff = (unwinddaemon::DataBuff*) full_buffer;
      unwinddaemon::UnwindCallChain(pid, reg_mask, data_buff, client_sockfd);
    }
  }
  close(client_sockfd);
}
