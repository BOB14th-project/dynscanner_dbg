#pragma once

#include <cstdint>
#include <variant>

namespace dynscanner {

enum class Architecture {
    kUnknown,
    kX86,
    kX86_64,
    kArm,
    kAArch64,
};

struct X86Registers {
    std::uint32_t eax{0};
    std::uint32_t ebx{0};
    std::uint32_t ecx{0};
    std::uint32_t edx{0};
    std::uint32_t esi{0};
    std::uint32_t edi{0};
    std::uint32_t ebp{0};
    std::uint32_t esp{0};
    std::uint32_t eip{0};
    std::uint32_t eflags{0};
};

struct X86_64Registers {
    std::uint64_t rax{0};
    std::uint64_t rbx{0};
    std::uint64_t rcx{0};
    std::uint64_t rdx{0};
    std::uint64_t rsi{0};
    std::uint64_t rdi{0};
    std::uint64_t rbp{0};
    std::uint64_t rsp{0};
    std::uint64_t r8{0};
    std::uint64_t r9{0};
    std::uint64_t r10{0};
    std::uint64_t r11{0};
    std::uint64_t r12{0};
    std::uint64_t r13{0};
    std::uint64_t r14{0};
    std::uint64_t r15{0};
    std::uint64_t rip{0};
    std::uint64_t rflags{0};
};

struct ArmRegisters {
    std::uint32_t r[16]{};  // r0-r15, where r15=PC
    std::uint32_t cpsr{0};
};

struct AArch64Registers {
    std::uint64_t x[31]{};  // x0-x30
    std::uint64_t sp{0};
    std::uint64_t pc{0};
    std::uint64_t pstate{0};
};

using RegisterState =
    std::variant<std::monostate, X86Registers, X86_64Registers, ArmRegisters,
                 AArch64Registers>;

inline const X86Registers* AsX86(const RegisterState& state) {
    return std::get_if<X86Registers>(&state);
}

inline X86Registers* AsX86(RegisterState& state) {
    return std::get_if<X86Registers>(&state);
}

inline const X86_64Registers* AsX86_64(const RegisterState& state) {
    return std::get_if<X86_64Registers>(&state);
}

inline X86_64Registers* AsX86_64(RegisterState& state) {
    return std::get_if<X86_64Registers>(&state);
}

inline const ArmRegisters* AsArm(const RegisterState& state) {
    return std::get_if<ArmRegisters>(&state);
}

inline ArmRegisters* AsArm(RegisterState& state) {
    return std::get_if<ArmRegisters>(&state);
}

inline const AArch64Registers* AsAArch64(const RegisterState& state) {
    return std::get_if<AArch64Registers>(&state);
}

inline AArch64Registers* AsAArch64(RegisterState& state) {
    return std::get_if<AArch64Registers>(&state);
}

}  // namespace dynscanner

