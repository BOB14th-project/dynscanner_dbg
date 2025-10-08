#include "linux/ptrace_debug_session.hpp"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#ifndef __WALL
#define __WALL 0
#endif

extern char** environ;

namespace dynscanner {
namespace {

constexpr std::size_t kPtraceWordSize = sizeof(long);
constexpr std::uint64_t kPtraceWordMask = ~(static_cast<std::uint64_t>(kPtraceWordSize) - 1);

std::vector<char*> BuildExecArguments(const LaunchOptions& options,
                                      std::vector<std::string>* storage) {
    storage->clear();
    storage->reserve(1 + options.arguments.size());
    storage->push_back(options.executable);
    for (const auto& arg : options.arguments) {
        storage->push_back(arg);
    }
    std::vector<char*> argv;
    argv.reserve(storage->size() + 1);
    for (auto& value : *storage) {
        argv.push_back(value.data());
    }
    argv.push_back(nullptr);
    return argv;
}

std::vector<char*> BuildEnvironment(const LaunchOptions& options,
                                    std::vector<std::string>* storage) {
    storage->clear();
    if (options.environment.empty()) {
        return {};
    }
    storage->reserve(options.environment.size());
    for (const auto& [key, value] : options.environment) {
        storage->push_back(key + "=" + value);
    }
    std::vector<char*> env;
    env.reserve(storage->size() + 1);
    for (auto& entry : *storage) {
        env.push_back(entry.data());
    }
    env.push_back(nullptr);
    return env;
}

bool WriteProcessWord(pid_t pid, std::uint64_t address, unsigned long word) {
    if (ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(address),
               reinterpret_cast<void*>(word)) != 0) {
        return false;
    }
    return true;
}

}  // namespace

std::unique_ptr<PtraceDebugSession> PtraceDebugSession::Launch(
    const LaunchOptions& options, std::string* error) {
    if (options.executable.empty()) {
        if (error) {
            *error = "실행 파일 경로가 비어 있습니다.";
        }
        return nullptr;
    }

    pid_t child = fork();
    if (child < 0) {
        if (error) {
            *error = std::string("fork 실패: ") + strerror(errno);
        }
        return nullptr;
    }

    if (child == 0) {
        if (options.working_directory) {
            if (chdir(options.working_directory->c_str()) != 0) {
                std::cerr << "작업 디렉터리 변경 실패: " << strerror(errno)
                          << std::endl;
                _exit(1);
            }
        }

        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
            std::cerr << "PTRACE_TRACEME 실패: " << strerror(errno) << std::endl;
            _exit(1);
        }

        raise(SIGSTOP);

        std::vector<std::string> argv_storage;
        auto argv = BuildExecArguments(options, &argv_storage);
        std::vector<std::string> env_storage;
        auto env = BuildEnvironment(options, &env_storage);
        char** envp = env.empty() ? environ : env.data();
        execve(options.executable.c_str(), argv.data(), envp);
        std::cerr << "execve 실패: " << strerror(errno) << std::endl;
        _exit(1);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        if (error) {
            *error = std::string("waitpid 실패: ") + strerror(errno);
        }
        kill(child, SIGKILL);
        return nullptr;
    }

    auto session = std::unique_ptr<PtraceDebugSession>(new PtraceDebugSession(child));
    if (!session->initialize_after_stop(child, status, error)) {
        kill(child, SIGKILL);
        return nullptr;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, nullptr,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT) != 0) {
        if (error) {
            *error = std::string("PTRACE_SETOPTIONS 실패: ") + strerror(errno);
        }
        session->terminate();
        return nullptr;
    }

    session->active_ = true;
    session->initial_stop_pending_ = true;
    if (error) {
        error->clear();
    }
    return session;
}

std::unique_ptr<PtraceDebugSession> PtraceDebugSession::Attach(
    pid_t pid, std::string* error) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        if (error) {
            *error = std::string("PTRACE_ATTACH 실패: ") + strerror(errno);
        }
        return nullptr;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        if (error) {
            *error = std::string("waitpid 실패: ") + strerror(errno);
        }
        return nullptr;
    }

    auto session = std::unique_ptr<PtraceDebugSession>(new PtraceDebugSession(pid));
    if (!session->initialize_after_stop(pid, status, error)) {
        session->terminate();
        return nullptr;
    }

    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT) != 0) {
        if (error) {
            *error = std::string("PTRACE_SETOPTIONS 실패: ") + strerror(errno);
        }
        session->terminate();
        return nullptr;
    }

    session->active_ = true;
    session->initial_stop_pending_ = true;
    if (error) {
        error->clear();
    }
    return session;
}

PtraceDebugSession::PtraceDebugSession(pid_t pid) : pid_(pid) {
#if defined(__x86_64__)
    architecture_ = Architecture::kX86_64;
#elif defined(__i386__)
    architecture_ = Architecture::kX86;
#else
    architecture_ = Architecture::kUnknown;
#endif
}

PtraceDebugSession::~PtraceDebugSession() {
    if (active_) {
        terminate();
    }
}

bool PtraceDebugSession::initialize_after_stop(pid_t tid, int status,
                                               std::string* error) {
    (void)tid;
    if (!WIFSTOPPED(status)) {
        if (error) {
            *error = "타깃 프로세스가 시작 전에 종료되었습니다.";
        }
        return false;
    }

    // ensure thread is stopped because of SIGSTOP/SIGTRAP
    return true;
}

bool PtraceDebugSession::wait_for_event(DebugEvent& event,
                                        std::chrono::milliseconds timeout) {
    if (!active_) {
        return false;
    }

    if (initial_stop_pending_) {
        initial_stop_pending_ = false;
        event = {};
        event.type = DebugEventType::kProcessStart;
        event.pid = pid_;
        event.tid = pid_;
        event.signal_number = SIGSTOP;
        return true;
    }

    const bool infinite_wait = timeout.count() < 0;
    const auto deadline =
        infinite_wait ? std::chrono::steady_clock::time_point::max()
                      : std::chrono::steady_clock::now() + timeout;

    while (true) {
        int status = 0;
        pid_t tid = waitpid(-1, &status,
                            WNOHANG | __WALL | WUNTRACED | WCONTINUED);
        if (tid == 0) {
            if (!infinite_wait && std::chrono::steady_clock::now() >= deadline) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (tid < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }

        if (!translate_wait_status(tid, status, event)) {
            continue;
        }

        event.pid = pid_;
        event.tid = tid;
        return true;
    }
}

bool PtraceDebugSession::resume(std::int64_t tid, std::int64_t signal) {
    if (!active_) {
        return false;
    }
    if (ptrace(PTRACE_CONT, static_cast<pid_t>(tid), nullptr,
               reinterpret_cast<void*>(signal)) != 0) {
        return false;
    }
    return true;
}

bool PtraceDebugSession::single_step(std::int64_t tid, std::int64_t signal) {
    if (!active_) {
        return false;
    }
    single_step_threads_[static_cast<pid_t>(tid)] = true;
    if (ptrace(PTRACE_SINGLESTEP, static_cast<pid_t>(tid), nullptr,
               reinterpret_cast<void*>(signal)) != 0) {
        single_step_threads_.erase(static_cast<pid_t>(tid));
        return false;
    }
    return true;
}

bool PtraceDebugSession::read_memory(std::uint64_t address, void* buffer,
                                     std::size_t size) {
    if (!active_ || buffer == nullptr || size == 0) {
        return false;
    }

    std::size_t offset = 0;
    auto* out = static_cast<std::uint8_t*>(buffer);
    while (offset < size) {
        const std::uint64_t current_address = address + offset;
        const std::uint64_t word_address = current_address & kPtraceWordMask;
        const std::size_t byte_offset =
            static_cast<std::size_t>(current_address - word_address);

        errno = 0;
        unsigned long word =
            ptrace(PTRACE_PEEKDATA, pid_, reinterpret_cast<void*>(word_address),
                   nullptr);
        if (errno != 0 && word == static_cast<unsigned long>(-1)) {
            return false;
        }

        const std::size_t bytes_available = kPtraceWordSize - byte_offset;
        const std::size_t bytes_to_copy =
            std::min(bytes_available, size - offset);
        for (std::size_t i = 0; i < bytes_to_copy; ++i) {
            const std::size_t shift = (byte_offset + i) * 8;
            out[offset + i] = static_cast<std::uint8_t>((word >> shift) & 0xFF);
        }

        offset += bytes_to_copy;
    }

    return true;
}

bool PtraceDebugSession::write_memory(std::uint64_t address, const void* buffer,
                                      std::size_t size) {
    if (!active_ || buffer == nullptr || size == 0) {
        return false;
    }

    std::size_t offset = 0;
    const auto* in = static_cast<const std::uint8_t*>(buffer);
    while (offset < size) {
        const std::uint64_t current_address = address + offset;
        const std::uint64_t word_address = current_address & kPtraceWordMask;
        const std::size_t byte_offset =
            static_cast<std::size_t>(current_address - word_address);

        errno = 0;
        unsigned long word =
            ptrace(PTRACE_PEEKDATA, pid_, reinterpret_cast<void*>(word_address),
                   nullptr);
        if (errno != 0 && word == static_cast<unsigned long>(-1)) {
            return false;
        }

        const std::size_t bytes_available = kPtraceWordSize - byte_offset;
        const std::size_t bytes_to_write =
            std::min(bytes_available, size - offset);
        for (std::size_t i = 0; i < bytes_to_write; ++i) {
            const std::size_t shift = (byte_offset + i) * 8;
            const unsigned long mask =
                static_cast<unsigned long>(0xFF) << shift;
            unsigned long value = static_cast<unsigned long>(in[offset + i])
                                  << shift;
            word = (word & ~mask) | value;
        }

        if (!WriteProcessWord(pid_, word_address, word)) {
            return false;
        }

        offset += bytes_to_write;
    }

    return true;
}

bool PtraceDebugSession::set_breakpoint(std::uint64_t address) {
    if (!active_) {
        return false;
    }

#if defined(__x86_64__) || defined(__i386__)
    if (breakpoints_.find(address) != breakpoints_.end()) {
        return true;
    }

    const std::uint64_t word_address = address & kPtraceWordMask;
    const std::uint8_t offset =
        static_cast<std::uint8_t>(address - word_address);

    errno = 0;
    unsigned long word =
        ptrace(PTRACE_PEEKTEXT, pid_, reinterpret_cast<void*>(word_address),
               nullptr);
    if (errno != 0 && word == static_cast<unsigned long>(-1)) {
        return false;
    }

    BreakpointInfo info{word_address, word, offset};
    const unsigned long trap_opcode = 0xCCUL;
    const std::size_t shift = static_cast<std::size_t>(offset) * 8;
    const unsigned long mask = static_cast<unsigned long>(0xFF) << shift;
    word = (word & ~mask) | (trap_opcode << shift);

    if (!WriteProcessWord(pid_, word_address, word)) {
        return false;
    }

    breakpoints_.emplace(address, info);
    return true;
#else
    (void)address;
    return false;
#endif
}

bool PtraceDebugSession::remove_breakpoint(std::uint64_t address) {
    if (!active_) {
        return false;
    }

    auto it = breakpoints_.find(address);
    if (it == breakpoints_.end()) {
        return false;
    }

    const BreakpointInfo& info = it->second;
    if (!WriteProcessWord(pid_, info.word_address, info.original_data)) {
        return false;
    }

    breakpoints_.erase(it);
    return true;
}

bool PtraceDebugSession::get_thread_registers(std::int64_t tid,
                                              RegisterState& state) {
    if (!active_) {
        return false;
    }
    return fill_registers(static_cast<pid_t>(tid), state);
}

bool PtraceDebugSession::set_thread_registers(std::int64_t tid,
                                              const RegisterState& state) {
    if (!active_) {
        return false;
    }
    return apply_registers(static_cast<pid_t>(tid), state);
}

Architecture PtraceDebugSession::architecture() const { return architecture_; }

bool PtraceDebugSession::terminate() {
    if (!active_) {
        return true;
    }

    restore_all_breakpoints();
    if (kill(pid_, SIGKILL) != 0) {
        return false;
    }

    int status = 0;
    waitpid(pid_, &status, 0);
    active_ = false;
    return true;
}

bool PtraceDebugSession::detach() {
    if (!active_) {
        return true;
    }

    restore_all_breakpoints();
    if (ptrace(PTRACE_DETACH, pid_, nullptr, nullptr) != 0) {
        return false;
    }
    active_ = false;
    return true;
}

bool PtraceDebugSession::translate_wait_status(pid_t tid, int status,
                                               DebugEvent& event) {
    if (WIFEXITED(status)) {
        event.type = DebugEventType::kProcessExit;
        event.exit_code = WEXITSTATUS(status);
        active_ = false;
        return true;
    }
    if (WIFSIGNALED(status)) {
        event.type = DebugEventType::kSignal;
        event.signal_number = WTERMSIG(status);
        active_ = false;
        return true;
    }
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP) {
            auto it = single_step_threads_.find(tid);
            if (it != single_step_threads_.end()) {
                single_step_threads_.erase(it);
                event.type = DebugEventType::kSingleStep;
                std::uint64_t pc = 0;
                if (fetch_program_counter(tid, pc)) {
                    event.address = pc;
                }
                return true;
            }

            std::uint64_t pc = 0;
            if (!fetch_program_counter(tid, pc)) {
                return false;
            }
#if defined(__x86_64__) || defined(__i386__)
            if (pc > 0) {
                pc -= 1;
            }
#endif
            event.type = DebugEventType::kBreakpoint;
            event.address = pc;
            event.signal_number = sig;
            return true;
        }

        if (sig == SIGSTOP) {
            event.type = DebugEventType::kThreadStart;
            event.signal_number = sig;
            return true;
        }

        event.type = DebugEventType::kSignal;
        event.signal_number = sig;
        return true;
    }

    event.type = DebugEventType::kUnknown;
    return true;
}

bool PtraceDebugSession::fetch_program_counter(pid_t tid, std::uint64_t& pc) {
#if defined(__x86_64__)
    user_regs_struct regs {};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != 0) {
        return false;
    }
    pc = regs.rip;
    return true;
#elif defined(__i386__)
    user_regs_struct regs {};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != 0) {
        return false;
    }
    pc = regs.eip;
    return true;
#else
    (void)tid;
    (void)pc;
    return false;
#endif
}

bool PtraceDebugSession::apply_registers(pid_t tid, const RegisterState& state) {
#if defined(__x86_64__)
    if (const auto* regs64 = AsX86_64(state)) {
        user_regs_struct native {};
        native.rax = regs64->rax;
        native.rbx = regs64->rbx;
        native.rcx = regs64->rcx;
        native.rdx = regs64->rdx;
        native.rsi = regs64->rsi;
        native.rdi = regs64->rdi;
        native.rbp = regs64->rbp;
        native.rsp = regs64->rsp;
        native.r8 = regs64->r8;
        native.r9 = regs64->r9;
        native.r10 = regs64->r10;
        native.r11 = regs64->r11;
        native.r12 = regs64->r12;
        native.r13 = regs64->r13;
        native.r14 = regs64->r14;
        native.r15 = regs64->r15;
        native.rip = regs64->rip;
        native.eflags = regs64->rflags;
        if (ptrace(PTRACE_SETREGS, tid, nullptr, &native) != 0) {
            return false;
        }
        return true;
    }
    return false;
#elif defined(__i386__)
    if (const auto* regs32 = AsX86(state)) {
        user_regs_struct native {};
        native.eax = regs32->eax;
        native.ebx = regs32->ebx;
        native.ecx = regs32->ecx;
        native.edx = regs32->edx;
        native.esi = regs32->esi;
        native.edi = regs32->edi;
        native.ebp = regs32->ebp;
        native.esp = regs32->esp;
        native.eip = regs32->eip;
        native.eflags = regs32->eflags;
        if (ptrace(PTRACE_SETREGS, tid, nullptr, &native) != 0) {
            return false;
        }
        return true;
    }
    return false;
#else
    (void)tid;
    (void)state;
    return false;
#endif
}

bool PtraceDebugSession::fill_registers(pid_t tid, RegisterState& state) {
#if defined(__x86_64__)
    user_regs_struct native {};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &native) != 0) {
        return false;
    }
    X86_64Registers regs;
    regs.rax = native.rax;
    regs.rbx = native.rbx;
    regs.rcx = native.rcx;
    regs.rdx = native.rdx;
    regs.rsi = native.rsi;
    regs.rdi = native.rdi;
    regs.rbp = native.rbp;
    regs.rsp = native.rsp;
    regs.r8 = native.r8;
    regs.r9 = native.r9;
    regs.r10 = native.r10;
    regs.r11 = native.r11;
    regs.r12 = native.r12;
    regs.r13 = native.r13;
    regs.r14 = native.r14;
    regs.r15 = native.r15;
    regs.rip = native.rip;
    regs.rflags = native.eflags;
    state = regs;
    return true;
#elif defined(__i386__)
    user_regs_struct native {};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &native) != 0) {
        return false;
    }
    X86Registers regs;
    regs.eax = native.eax;
    regs.ebx = native.ebx;
    regs.ecx = native.ecx;
    regs.edx = native.edx;
    regs.esi = native.esi;
    regs.edi = native.edi;
    regs.ebp = native.ebp;
    regs.esp = native.esp;
    regs.eip = native.eip;
    regs.eflags = native.eflags;
    state = regs;
    return true;
#else
    (void)tid;
    (void)state;
    return false;
#endif
}

void PtraceDebugSession::restore_all_breakpoints() {
    for (const auto& [address, info] : breakpoints_) {
        WriteProcessWord(pid_, info.word_address, info.original_data);
    }
    breakpoints_.clear();
}

}  // namespace dynscanner

