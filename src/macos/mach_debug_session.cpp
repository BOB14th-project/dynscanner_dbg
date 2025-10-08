#include "macos/mach_debug_session.hpp"

#include <mach/mach_exc.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <spawn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>

#include <csignal>

extern char** environ;

namespace dynscanner {
namespace {

MachDebugSession* g_current_session = nullptr;

std::vector<char*> BuildArgv(const LaunchOptions& options,
                             std::vector<std::string>& storage) {
    storage.clear();
    storage.reserve(1 + options.arguments.size());
    storage.push_back(options.executable);
    for (const auto& arg : options.arguments) {
        storage.emplace_back(arg);
    }
    std::vector<char*> argv;
    argv.reserve(storage.size() + 1);
    for (auto& item : storage) {
        argv.push_back(item.data());
    }
    argv.push_back(nullptr);
    return argv;
}

std::vector<char*> BuildEnvironment(
    const std::map<std::string, std::string>& environment,
    std::vector<std::string>& storage) {
    storage.clear();
    if (environment.empty()) {
        return {nullptr};
    }
    storage.reserve(environment.size());
    for (const auto& [key, value] : environment) {
        storage.push_back(key + "=" + value);
    }
    std::vector<char*> envp;
    envp.reserve(storage.size() + 1);
    for (auto& item : storage) {
        envp.push_back(item.data());
    }
    envp.push_back(nullptr);
    return envp;
}

Architecture DetectArchitecture(task_t task, thread_act_t thread) {
    if (thread == MACH_PORT_NULL) {
        return Architecture::kUnknown;
    }
#if defined(__APPLE__)
    {
        x86_thread_state64_t state64;
        mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&state64,
                              &count) == KERN_SUCCESS) {
            return Architecture::kX86_64;
        }
    }
    {
        x86_thread_state32_t state32;
        mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;
        if (thread_get_state(thread, x86_THREAD_STATE32, (thread_state_t)&state32,
                              &count) == KERN_SUCCESS) {
            return Architecture::kX86;
        }
    }
#if defined(ARM_THREAD_STATE64_COUNT)
    {
        arm_thread_state64_t state64;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, ARM_THREAD_STATE64,
                              (thread_state_t)&state64, &count) == KERN_SUCCESS) {
            return Architecture::kAArch64;
        }
    }
#endif
#endif
    (void)task;
    return Architecture::kUnknown;
}

std::vector<std::uint8_t> TrapOpcode(Architecture arch) {
    switch (arch) {
        case Architecture::kX86:
        case Architecture::kX86_64:
            return {0xCC};
        case Architecture::kArm:
            return {0xFE, 0xDE};
        case Architecture::kAArch64:
            return {0x00, 0x00, 0x3D, 0xD4};
        default:
            return {0xCC};
    }
}

}  // namespace

std::unique_ptr<MachDebugSession> MachDebugSession::Launch(
    const LaunchOptions& options, std::string* error) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    short flags = POSIX_SPAWN_START_SUSPENDED;
    posix_spawnattr_setflags(&attr, flags);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (options.working_directory) {
#ifdef POSIX_SPAWN_SETSIGDEF
        (void)0;
#endif
#ifdef POSIX_SPAWN_CHDIR
        posix_spawn_file_actions_addchdir_np(&actions,
                                             options.working_directory->c_str());
#endif
    }

    std::vector<std::string> argv_storage;
    std::vector<char*> argv = BuildArgv(options, argv_storage);

    std::vector<std::string> env_storage;
    std::vector<char*> envp = BuildEnvironment(options.environment, env_storage);
    char* const* env_ptr = envp.empty() || envp[0] == nullptr ? environ : envp.data();

    pid_t child = -1;
    int spawn_result = posix_spawn(&child, options.executable.c_str(), &actions,
                                   &attr, argv.data(), env_ptr);

    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);

    if (spawn_result != 0) {
        if (error) {
            *error = "posix_spawn 실패: " + std::to_string(spawn_result);
        }
        return nullptr;
    }

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), child, &task);
    if (kr != KERN_SUCCESS) {
        if (error) {
            *error = "task_for_pid 실패: " + std::to_string(kr);
        }
        kill(child, SIGKILL);
        return nullptr;
    }

    auto session = std::unique_ptr<MachDebugSession>(
        new MachDebugSession(task, child, false));
    if (!session->initialize(error)) {
        kill(child, SIGKILL);
        return nullptr;
    }

    task_resume(task);
    return session;
}

std::unique_ptr<MachDebugSession> MachDebugSession::Attach(pid_t pid,
                                                           std::string* error) {
    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) {
        if (error) {
            *error = "ptrace(PT_ATTACHEXC) 실패";
        }
        return nullptr;
    }
    int status = 0;
    waitpid(pid, &status, 0);

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        if (error) {
            *error = "task_for_pid 실패: " + std::to_string(kr);
        }
        ptrace(PT_DETACH, pid, 0, 0);
        return nullptr;
    }

    auto session = std::unique_ptr<MachDebugSession>(
        new MachDebugSession(task, pid, true));
    if (!session->initialize(error)) {
        ptrace(PT_DETACH, pid, 0, 0);
        return nullptr;
    }
    return session;
}

MachDebugSession::MachDebugSession(task_t task, pid_t pid, bool attached)
    : task_(task), pid_(pid), attached_(attached) {}

MachDebugSession::~MachDebugSession() {
    restore_all_breakpoints();
    for (auto& [tid, port] : threads_) {
        mach_port_deallocate(mach_task_self(), port);
    }
    if (exception_port_ != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), exception_port_);
    }
    if (!attached_) {
        task_terminate(task_);
    }
}

bool MachDebugSession::initialize(std::string* error) {
    if (!configure_exception_port(error)) {
        return false;
    }
    if (!refresh_threads()) {
        if (error) {
            *error = "스레드 정보를 가져오지 못했습니다.";
        }
        return false;
    }
    if (threads_.empty()) {
        if (error) {
            *error = "활성 스레드가 없습니다.";
        }
        return false;
    }
    architecture_ = DetectArchitecture(task_, threads_.begin()->second);
    if (architecture_ == Architecture::kUnknown) {
        if (error) {
            *error = "지원하지 않는 아키텍처입니다.";
        }
        return false;
    }
    active_ = true;
    return true;
}

bool MachDebugSession::configure_exception_port(std::string* error) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                                          &port);
    if (kr != KERN_SUCCESS) {
        if (error) {
            *error = "mach_port_allocate 실패: " + std::to_string(kr);
        }
        return false;
    }

    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        if (error) {
            *error = "mach_port_insert_right 실패: " + std::to_string(kr);
        }
        mach_port_deallocate(mach_task_self(), port);
        return false;
    }

    kr = task_set_exception_ports(
        task_, EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_SOFTWARE |
                   EXC_MASK_ARITHMETIC,
        port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
    if (kr != KERN_SUCCESS) {
        if (error) {
            *error = "task_set_exception_ports 실패: " + std::to_string(kr);
        }
        mach_port_deallocate(mach_task_self(), port);
        return false;
    }

    exception_port_ = port;
    return true;
}

bool MachDebugSession::refresh_threads() {
    thread_act_array_t list = nullptr;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(task_, &list, &count);
    if (kr != KERN_SUCCESS) {
        return false;
    }

    for (auto& [tid, port] : threads_) {
        mach_port_deallocate(mach_task_self(), port);
    }
    threads_.clear();

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        thread_identifier_info_data_t info;
        mach_msg_type_number_t info_count = THREAD_IDENTIFIER_INFO_COUNT;
        if (thread_info(list[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&info,
                        &info_count) == KERN_SUCCESS) {
            threads_[info.thread_id] = list[i];
        } else {
            mach_port_deallocate(mach_task_self(), list[i]);
        }
    }

    vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(list),
                  sizeof(thread_act_t) * count);
    return true;
}

thread_act_t MachDebugSession::thread_from_id(std::int64_t tid) const {
    auto it = threads_.find(tid);
    if (it == threads_.end()) {
        return MACH_PORT_NULL;
    }
    return it->second;
}

bool MachDebugSession::read_thread_state(thread_act_t thread,
                                         RegisterState& state) {
    if (thread == MACH_PORT_NULL) {
        return false;
    }
    switch (architecture_) {
        case Architecture::kX86_64: {
            x86_thread_state64_t regs;
            mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
            if (thread_get_state(thread, x86_THREAD_STATE64,
                                  (thread_state_t)&regs, &count) != KERN_SUCCESS) {
                return false;
            }
            X86_64Registers out{};
            out.rax = regs.rax;
            out.rbx = regs.rbx;
            out.rcx = regs.rcx;
            out.rdx = regs.rdx;
            out.rsi = regs.rsi;
            out.rdi = regs.rdi;
            out.rbp = regs.rbp;
            out.rsp = regs.rsp;
            out.r8 = regs.r8;
            out.r9 = regs.r9;
            out.r10 = regs.r10;
            out.r11 = regs.r11;
            out.r12 = regs.r12;
            out.r13 = regs.r13;
            out.r14 = regs.r14;
            out.r15 = regs.r15;
            out.rip = regs.rip;
            out.rflags = regs.rflags;
            state = out;
            return true;
        }
        case Architecture::kX86: {
            x86_thread_state32_t regs;
            mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;
            if (thread_get_state(thread, x86_THREAD_STATE32,
                                  (thread_state_t)&regs, &count) != KERN_SUCCESS) {
                return false;
            }
            X86Registers out{};
            out.eax = regs.eax;
            out.ebx = regs.ebx;
            out.ecx = regs.ecx;
            out.edx = regs.edx;
            out.esi = regs.esi;
            out.edi = regs.edi;
            out.ebp = regs.ebp;
            out.esp = regs.esp;
            out.eip = regs.eip;
            out.eflags = regs.eflags;
            state = out;
            return true;
        }
#if defined(ARM_THREAD_STATE64_COUNT)
        case Architecture::kAArch64: {
            arm_thread_state64_t regs;
            mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(thread, ARM_THREAD_STATE64,
                                  (thread_state_t)&regs, &count) != KERN_SUCCESS) {
                return false;
            }
            AArch64Registers out{};
            for (int i = 0; i < 31; ++i) {
                out.x[i] = regs.__x[i];
            }
            out.sp = regs.__sp;
            out.pc = regs.__pc;
            out.pstate = regs.__cpsr;
            state = out;
            return true;
        }
#endif
        default:
            return false;
    }
}

bool MachDebugSession::write_thread_state(thread_act_t thread,
                                          const RegisterState& state) {
    if (thread == MACH_PORT_NULL) {
        return false;
    }
    switch (architecture_) {
        case Architecture::kX86_64: {
            x86_thread_state64_t regs;
            mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
            if (thread_get_state(thread, x86_THREAD_STATE64,
                                  (thread_state_t)&regs, &count) != KERN_SUCCESS) {
                return false;
            }
            if (const auto* in = AsX86_64(state)) {
                regs.rax = in->rax;
                regs.rbx = in->rbx;
                regs.rcx = in->rcx;
                regs.rdx = in->rdx;
                regs.rsi = in->rsi;
                regs.rdi = in->rdi;
                regs.rbp = in->rbp;
                regs.rsp = in->rsp;
                regs.r8 = in->r8;
                regs.r9 = in->r9;
                regs.r10 = in->r10;
                regs.r11 = in->r11;
                regs.r12 = in->r12;
                regs.r13 = in->r13;
                regs.r14 = in->r14;
                regs.r15 = in->r15;
                regs.rip = in->rip;
                regs.rflags = in->rflags;
                return thread_set_state(thread, x86_THREAD_STATE64,
                                         (thread_state_t)&regs, count) ==
                       KERN_SUCCESS;
            }
            return false;
        }
        case Architecture::kX86: {
            x86_thread_state32_t regs;
            mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;
            if (thread_get_state(thread, x86_THREAD_STATE32,
                                  (thread_state_t)&regs, &count) != KERN_SUCCESS) {
                return false;
            }
            if (const auto* in = AsX86(state)) {
                regs.eax = in->eax;
                regs.ebx = in->ebx;
                regs.ecx = in->ecx;
                regs.edx = in->edx;
                regs.esi = in->esi;
                regs.edi = in->edi;
                regs.ebp = in->ebp;
                regs.esp = in->esp;
                regs.eip = in->eip;
                regs.eflags = in->eflags;
                return thread_set_state(thread, x86_THREAD_STATE32,
                                         (thread_state_t)&regs, count) ==
                       KERN_SUCCESS;
            }
            return false;
        }
#if defined(ARM_THREAD_STATE64_COUNT)
        case Architecture::kAArch64: {
            arm_thread_state64_t regs;
            mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(thread, ARM_THREAD_STATE64,
                                  (thread_state_t)&regs, &count) != KERN_SUCCESS) {
                return false;
            }
            if (const auto* in = AsAArch64(state)) {
                for (int i = 0; i < 31; ++i) {
                    regs.__x[i] = in->x[i];
                }
                regs.__sp = in->sp;
                regs.__pc = in->pc;
                regs.__cpsr = static_cast<uint32_t>(in->pstate);
                return thread_set_state(thread, ARM_THREAD_STATE64,
                                         (thread_state_t)&regs, count) ==
                       KERN_SUCCESS;
            }
            return false;
        }
#endif
        default:
            return false;
    }
}

bool MachDebugSession::read_memory(std::uint64_t address, void* buffer,
                                   std::size_t size) {
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(task_, address, size,
                                              reinterpret_cast<mach_vm_address_t>(
                                                  buffer),
                                              &out);
    return kr == KERN_SUCCESS && out == size;
}

bool MachDebugSession::write_memory(std::uint64_t address, const void* buffer,
                                    std::size_t size) {
    kern_return_t kr = mach_vm_write(task_, address,
                                     reinterpret_cast<vm_offset_t>(buffer),
                                     static_cast<mach_msg_type_number_t>(size));
    return kr == KERN_SUCCESS;
}

bool MachDebugSession::read_bytes(std::uint64_t address, std::uint8_t* data,
                                  std::size_t size) {
    return read_memory(address, data, size);
}

bool MachDebugSession::write_bytes(std::uint64_t address,
                                   const std::uint8_t* data,
                                   std::size_t size) {
    return write_memory(address, data, size);
}

std::vector<std::uint8_t> MachDebugSession::breakpoint_opcode() const {
    return TrapOpcode(architecture_);
}

bool MachDebugSession::set_breakpoint(std::uint64_t address) {
    auto opcode = breakpoint_opcode();
    if (opcode.empty()) {
        return false;
    }
    std::vector<std::uint8_t> original(opcode.size());
    if (!read_bytes(address, original.data(), original.size())) {
        return false;
    }
    if (!write_bytes(address, opcode.data(), opcode.size())) {
        return false;
    }
    breakpoints_[address] = {original, true};
    return true;
}

bool MachDebugSession::remove_breakpoint(std::uint64_t address) {
    auto it = breakpoints_.find(address);
    if (it == breakpoints_.end()) {
        return false;
    }
    if (it->second.installed) {
        write_bytes(address, it->second.original.data(),
                    it->second.original.size());
    }
    breakpoints_.erase(it);
    return true;
}

bool MachDebugSession::wait_for_event(DebugEvent& event,
                                      std::chrono::milliseconds timeout) {
    if (!active_) {
        return false;
    }
    struct Request {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t thread;
        mach_msg_port_descriptor_t task;
        NDR_record_t ndr;
        exception_type_t exception;
        mach_msg_type_number_t code_count;
        mach_exception_data_type_t code[2];
        int flavor;
        mach_msg_type_number_t old_state_count;
        natural_t old_state[THREAD_STATE_MAX];
    } request{};
    struct Reply {
        mach_msg_header_t header;
        NDR_record_t ndr;
        kern_return_t ret;
        int flavor;
        mach_msg_type_number_t new_state_count;
        natural_t new_state[THREAD_STATE_MAX];
    } reply{};

    mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_LARGE;
    mach_msg_timeout_t wait = MACH_MSG_TIMEOUT_NONE;
    if (timeout.count() >= 0) {
        options |= MACH_RCV_TIMEOUT;
        wait = static_cast<mach_msg_timeout_t>(timeout.count());
    }

    mach_msg_return_t mr = mach_msg(&request.header, options, 0, sizeof(request),
                                    exception_port_, wait, MACH_PORT_NULL);
    if (mr == MACH_RCV_TIMED_OUT) {
        return false;
    }
    if (mr != MACH_MSG_SUCCESS) {
        return false;
    }

    pending_.valid = false;
    g_current_session = this;
    bool handled = mach_exc_server(&request.header, &reply.header);
    g_current_session = nullptr;
    if (!handled || !pending_.valid) {
        return false;
    }

    pending_.reply_header = reply.header;
    pending_.ndr = reply.ndr;
    pending_.ret = reply.ret;
    pending_.flavor = reply.flavor;
    pending_.state_count = reply.new_state_count;
    std::copy(reply.new_state, reply.new_state + reply.new_state_count,
              pending_.state.begin());
    pending_.request_header = request.header;

    event = pending_.event;
    return true;
}

bool MachDebugSession::send_pending_reply() {
    if (!pending_.valid) {
        return false;
    }
    struct Reply {
        mach_msg_header_t header;
        NDR_record_t ndr;
        kern_return_t ret;
        int flavor;
        mach_msg_type_number_t new_state_count;
        natural_t new_state[THREAD_STATE_MAX];
    } reply{};
    reply.header = pending_.reply_header;
    reply.ndr = pending_.ndr;
    reply.ret = pending_.ret;
    reply.flavor = pending_.flavor;
    reply.new_state_count = pending_.state_count;
    std::copy(pending_.state.begin(),
              pending_.state.begin() + pending_.state_count, reply.new_state);

    kern_return_t kr = mach_msg(&reply.header, MACH_SEND_MSG, reply.header.msgh_size,
                                0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
                                MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        return false;
    }
    pending_.valid = false;
    return true;
}

bool MachDebugSession::resume(std::int64_t /*tid*/, std::int64_t /*signal*/) {
    return send_pending_reply();
}

bool MachDebugSession::single_step(std::int64_t /*tid*/,
                                   std::int64_t /*signal*/) {
    if (!pending_.valid) {
        return false;
    }
    if (architecture_ == Architecture::kX86_64 &&
        pending_.flavor == x86_THREAD_STATE64) {
        auto* state =
            reinterpret_cast<x86_thread_state64_t*>(pending_.state.data());
        state->rflags |= 0x100;
        pending_.state_count = x86_THREAD_STATE64_COUNT;
    } else if (architecture_ == Architecture::kX86 &&
               pending_.flavor == x86_THREAD_STATE32) {
        auto* state =
            reinterpret_cast<x86_thread_state32_t*>(pending_.state.data());
        state->eflags |= 0x100;
        pending_.state_count = x86_THREAD_STATE32_COUNT;
    } else {
        if (ptrace(PT_STEP, pid_, (caddr_t)1, 0) != 0) {
            return false;
        }
    }
    return send_pending_reply();
}

bool MachDebugSession::get_thread_registers(std::int64_t tid,
                                            RegisterState& state) {
    auto thread = thread_from_id(tid);
    return read_thread_state(thread, state);
}

bool MachDebugSession::set_thread_registers(
    std::int64_t tid, const RegisterState& state) {
    auto thread = thread_from_id(tid);
    return write_thread_state(thread, state);
}

Architecture MachDebugSession::architecture() const { return architecture_; }

bool MachDebugSession::terminate() {
    if (!task_) {
        return false;
    }
    kern_return_t kr = task_terminate(task_);
    active_ = false;
    return kr == KERN_SUCCESS;
}

bool MachDebugSession::detach() {
    if (attached_) {
        ptrace(PT_DETACH, pid_, (caddr_t)1, 0);
    }
    active_ = false;
    return true;
}

std::vector<std::uint8_t> MachDebugSession::breakpoint_opcode() const {
    return TrapOpcode(architecture_);
}

void MachDebugSession::restore_all_breakpoints() {
    for (auto& [address, info] : breakpoints_) {
        if (info.installed) {
            write_bytes(address, info.original.data(), info.original.size());
        }
    }
    breakpoints_.clear();
}

kern_return_t MachDebugSession::HandleException(
    mach_port_t thread, mach_port_t task, exception_type_t exception,
    const mach_exception_data_type_t* code, mach_msg_type_number_t code_count,
    int* flavor, mach_msg_type_number_t* state_count, natural_t* state) {
    pending_.thread_port = thread;
    pending_.task_port = task;
    pending_.exception = exception;
    pending_.code_count = code_count;
    for (mach_msg_type_number_t i = 0; i < code_count && i < 2; ++i) {
        pending_.code[i] = code[i];
    }
    pending_.flavor = *flavor;
    pending_.state_count = *state_count;
    std::copy(state, state + *state_count, pending_.state.begin());

    DebugEvent evt{};
    evt.pid = pid_;

    thread_identifier_info_data_t info;
    mach_msg_type_number_t info_count = THREAD_IDENTIFIER_INFO_COUNT;
    if (thread_info(thread, THREAD_IDENTIFIER_INFO, (thread_info_t)&info,
                    &info_count) == KERN_SUCCESS) {
        evt.tid = info.thread_id;
        threads_[info.thread_id] = thread;
    }

    evt.type = DebugEventType::kUnknown;
    if (exception == EXC_BREAKPOINT) {
        evt.type = DebugEventType::kBreakpoint;
        if (*flavor == x86_THREAD_STATE64) {
            const auto* regs =
                reinterpret_cast<const x86_thread_state64_t*>(state);
            evt.address = regs->rip ? regs->rip - 1 : 0;
        } else if (*flavor == x86_THREAD_STATE32) {
            const auto* regs =
                reinterpret_cast<const x86_thread_state32_t*>(state);
            evt.address = regs->eip ? regs->eip - 1 : 0;
        } else if (*flavor == ARM_THREAD_STATE64) {
            const auto* regs =
                reinterpret_cast<const arm_thread_state64_t*>(state);
            evt.address = regs->__pc ? regs->__pc - 4 : 0;
        }
    } else if (exception == EXC_SOFTWARE && code_count > 1 &&
               code[0] == EXC_SOFT_SIGNAL) {
        evt.type = DebugEventType::kSignal;
        evt.signal_number = code[1];
    } else if (exception == EXC_BAD_ACCESS) {
        evt.type = DebugEventType::kSignal;
        evt.signal_number = SIGSEGV;
    }

    pending_.event = evt;
    pending_.valid = true;
    return KERN_SUCCESS;
}

}  // namespace dynscanner

extern "C" kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t code_count, int* flavor,
    mach_msg_type_number_t* state_count, natural_t* state) {
    if (!dynscanner::g_current_session) {
        return KERN_FAILURE;
    }
    return dynscanner::g_current_session->HandleException(
        thread, task, exception, code, code_count, flavor, state_count, state);
}

