
#include <inttypes.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>

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
#include <unwindstack/Arch.h>

// Use the demangler from libc++.
extern "C" char* __cxa_demangle(const char*, char*, size_t*, int* status);

namespace unwinddaemon {


class UnwinderWithPC : public unwindstack::Unwinder {
 public:
  UnwinderWithPC(size_t max_frames, unwindstack::Maps* maps, unwindstack::Regs* regs, std::shared_ptr<unwindstack::Memory> process_memory, bool show_pc)
      : unwindstack::Unwinder(max_frames, maps, regs, process_memory), show_pc(show_pc) {}
  virtual ~UnwinderWithPC() = default;

  bool Init();
  
  std::string FormatFrame(size_t frame_num) const;

 protected:
  bool show_pc = false;
};

std::string UnwinderWithPC::FormatFrame(size_t frame_num) const {
  if (frame_num >= frames_.size()) {
    return "";
  }
  const unwindstack::FrameData& frame = frames_[frame_num];

  std::string data;
  if (show_pc) {
    if (ArchIs32Bit(arch_)) {
      data += android::base::StringPrintf("  #%02zu pc %08" PRIx64 " %08" PRIx64, frame.num, frame.pc, frame.rel_pc);
    } else {
      data += android::base::StringPrintf("  #%02zu pc %016" PRIx64 " %016" PRIx64, frame.num, frame.pc, frame.rel_pc);
    }
  } else {
    if (ArchIs32Bit(arch_)) {
      data += android::base::StringPrintf("  #%02zu pc %08" PRIx64, frame.num, frame.rel_pc);
    } else {
      data += android::base::StringPrintf("  #%02zu pc %016" PRIx64, frame.num, frame.rel_pc);
    }
  }

  auto map_info = frame.map_info;
  if (map_info == nullptr) {
    // No valid map associated with this frame.
    data += "  <unknown>";
  } else if (!map_info->name().empty()) {
    data += "  ";
    data += map_info->GetFullName();
  } else {
    data += android::base::StringPrintf("  <anonymous:%" PRIx64 ">", map_info->start());
  }

  if (map_info != nullptr && map_info->elf_start_offset() != 0) {
    data += android::base::StringPrintf(" (offset 0x%" PRIx64 ")", map_info->elf_start_offset());
  }

  if (!frame.function_name.empty()) {
    char* demangled_name = __cxa_demangle(frame.function_name.c_str(), nullptr, nullptr, nullptr);
    if (demangled_name == nullptr) {
      data += " (";
      data += frame.function_name;
    } else {
      data += " (";
      data += demangled_name;
      free(demangled_name);
    }
    if (frame.function_offset != 0) {
      data += android::base::StringPrintf("+%" PRId64, frame.function_offset);
    }
    data += ')';
  }

  if (map_info != nullptr && display_build_id_) {
    std::string build_id = map_info->GetPrintableBuildID();
    if (!build_id.empty()) {
      data += " (BuildId: " + build_id + ')';
    }
  }
  return data;
}

struct UnwindOption {
    uint64_t abi;
    uint64_t stack_size;
    uint64_t dyn_size;
    uint64_t reg_mask;
    bool show_pc;
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
  // actually, don't need this
  // if (ScopedCurrentArch::GetCurrentArch() == ARCH_ARM64 && abi == PERF_SAMPLE_REGS_ABI_32) {
  //   // The kernel dumps arm64 regs, but we need arm regs. So map arm64 regs into arm regs.
  //   data[PERF_REG_ARM_PC] = data[PERF_REG_ARM64_PC];
  // }
}

bool RegSet::GetRegValue(size_t regno, uint64_t* value) const {
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

std::string DumpFrames(const UnwinderWithPC& unwinder) {
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

const char* UnwindCallChain(char* map_buffer, UnwindOption* opt, uint64_t* regs_buf, void* stack_buf) {
    const char* result = "";
    // std::cerr << "pid:" << pid << "reg_mask:" << opt->reg_mask << "abi:" << opt->abi << std::endl;
    RegSet regs(opt->abi, opt->reg_mask, regs_buf);

    uint64_t sp_reg_value;
    if (!regs.GetSpRegValue(&sp_reg_value)) {
        std::cerr << "can't get sp reg value";
        return result;
    }
    
    uint64_t stack_addr = sp_reg_value;
    size_t stack_size = opt->dyn_size;
    
    std::unique_ptr<unwindstack::Regs> unwind_regs(GetBacktraceRegs(regs));
    if (!unwind_regs) {
      return result;
    }
    std::shared_ptr<unwindstack::Memory> stack_memory = unwindstack::Memory::CreateOfflineMemory(
        reinterpret_cast<const uint8_t*>(stack_buf), stack_addr, stack_addr + stack_size
    );

    std::unique_ptr<unwindstack::Maps> maps;
    maps.reset(new unwindstack::BufferMaps(map_buffer));
    maps->Parse();
    UnwinderWithPC unwinder(512, maps.get(), unwind_regs.get(), stack_memory, opt->show_pc);
    // default is true
    // unwinder.SetResolveNames(false);
    unwinder.Unwind();
    std::string frame_info = DumpFrames(unwinder);
    // int len = frame_info.length();
    // send(client_sockfd, &len, 4, 0);
    // send(client_sockfd, frame_info.c_str(), len, 0);
    result = frame_info.c_str();
    return result;
}
}

__attribute__ ((visibility("default")))
extern "C" const char* StackPlz(char* map_buffer, void* opt, void* regs_buf, void* stack_buf) {
  return unwinddaemon::UnwindCallChain(map_buffer, (unwinddaemon::UnwindOption*) opt, (uint64_t*) regs_buf, stack_buf);
}