#include "windows/windbg_debug_session.hpp"

#include <psapi.h>
#include <tlhelp32.h>

#include <array>
#include <sstream>

namespace dynscanner {
namespace {

using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

Architecture MachineToArchitecture(USHORT machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:
            return Architecture::kX86;
        case IMAGE_FILE_MACHINE_AMD64:
            return Architecture::kX86_64;
        case IMAGE_FILE_MACHINE_ARM:
            return Architecture::kArm;
        case IMAGE_FILE_MACHINE_ARM64:
            return Architecture::kAArch64;
        default:
            return Architecture::kUnknown;
    }
}

std::wstring Utf8ToWide(const std::string& input) {
    if (input.empty()) {
        return std::wstring();
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, input.c_str(),
                                   static_cast<int>(input.size()), nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()),
                        result.data(), size);
    return result;
}

std::wstring BuildCommandLine(const LaunchOptions& options) {
    std::wostringstream ss;
    auto quote = [](const std::string& s) {
        bool needs_quote = s.find_first_of(" \"\t") != std::string::npos;
        std::string escaped;
        escaped.reserve(s.size() + 2);
        if (needs_quote) {
            escaped.push_back('"');
        }
        for (char ch : s) {
            if (ch == '"') {
                escaped.push_back('\\');
            }
            escaped.push_back(ch);
        }
        if (needs_quote) {
            escaped.push_back('"');
        }
        return Utf8ToWide(escaped);
    };

    ss << quote(options.executable);
    for (const auto& arg : options.arguments) {
        ss << L' ' << quote(arg);
    }
    return ss.str();
}

std::vector<wchar_t> BuildEnvironmentBlock(
    const std::map<std::string, std::string>& environment) {
    if (environment.empty()) {
        return std::vector<wchar_t>();
    }
    std::vector<wchar_t> block;
    for (const auto& [key, value] : environment) {
        std::wstring wkey = Utf8ToWide(key);
        std::wstring wvalue = Utf8ToWide(value);
        block.insert(block.end(), wkey.begin(), wkey.end());
        block.push_back(L'=');
        block.insert(block.end(), wvalue.begin(), wvalue.end());
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}

DWORD WaitTimeout(const std::chrono::milliseconds& timeout) {
    if (timeout.count() < 0) {
        return INFINITE;
    }
    if (timeout == std::chrono::milliseconds::zero()) {
        return 0;
    }
    return static_cast<DWORD>(timeout.count());
}

}  // namespace

std::unique_ptr<WinDbgDebugSession> WinDbgDebugSession::Launch(
    const LaunchOptions& options, std::string* error) {
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::wstring command_line = BuildCommandLine(options);
    std::wstring workdir = options.working_directory
                               ? Utf8ToWide(*options.working_directory)
                               : std::wstring();
    std::vector<wchar_t> env_block = BuildEnvironmentBlock(options.environment);

    std::wstring application = Utf8ToWide(options.executable);
    std::vector<wchar_t> cmd_buffer(command_line.begin(), command_line.end());
    cmd_buffer.push_back(L'\0');

    BOOL ok = CreateProcessW(
        application.empty() ? nullptr : application.c_str(), cmd_buffer.data(),
        nullptr, nullptr, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        env_block.empty() ? nullptr : env_block.data(),
        workdir.empty() ? nullptr : workdir.c_str(), &si, &pi);

    if (!ok) {
        if (error) {
            DWORD code = GetLastError();
            *error = "CreateProcessW 실패: " + std::to_string(code);
        }
        return nullptr;
    }

    auto session = std::unique_ptr<WinDbgDebugSession>(
        new WinDbgDebugSession(pi.hProcess, pi.dwProcessId, false));
    session->thread_handles_.emplace(pi.dwThreadId, pi.hThread);

    if (!session->initialize(error)) {
        TerminateProcess(pi.hProcess, 1);
        return nullptr;
    }

    ResumeThread(pi.hThread);
    return session;
}

std::unique_ptr<WinDbgDebugSession> WinDbgDebugSession::Attach(DWORD pid,
                                                               std::string* error) {
    if (!DebugActiveProcess(pid)) {
        if (error) {
            DWORD code = GetLastError();
            *error = "DebugActiveProcess 실패: " + std::to_string(code);
        }
        return nullptr;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process) {
        if (error) {
            DWORD code = GetLastError();
            *error = "OpenProcess 실패: " + std::to_string(code);
        }
        DebugActiveProcessStop(pid);
        return nullptr;
    }

    auto session = std::unique_ptr<WinDbgDebugSession>(
        new WinDbgDebugSession(process, pid, true));

    if (!session->initialize(error)) {
        session.reset();
        DebugActiveProcessStop(pid);
        return nullptr;
    }

    return session;
}

WinDbgDebugSession::WinDbgDebugSession(HANDLE process, DWORD pid, bool attached)
    : process_handle_(process), pid_(pid), attached_(attached) {
    ZeroMemory(&last_event_, sizeof(last_event_));
}

WinDbgDebugSession::~WinDbgDebugSession() {
    restore_all_breakpoints();
    for (auto& [tid, handle] : thread_handles_) {
        if (handle) {
            CloseHandle(handle);
        }
    }
    if (process_handle_) {
        CloseHandle(process_handle_);
    }
    if (attached_) {
        DebugActiveProcessStop(pid_);
    }
}

bool WinDbgDebugSession::initialize(std::string* error) {
    active_ = true;
    DebugSetProcessKillOnExit(FALSE);
    if (!update_architecture()) {
        if (error) {
            *error = "프로세스 아키텍처를 확인하지 못했습니다.";
        }
        return false;
    }
    return true;
}

bool WinDbgDebugSession::update_architecture() {
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (kernel) {
        auto fn = reinterpret_cast<IsWow64Process2Fn>(
            GetProcAddress(kernel, "IsWow64Process2"));
        if (fn) {
            USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (fn(process_handle_, &process_machine, &native_machine)) {
                if (process_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
                    architecture_ = MachineToArchitecture(process_machine);
                    return architecture_ != Architecture::kUnknown;
                }
                architecture_ = MachineToArchitecture(native_machine);
                return architecture_ != Architecture::kUnknown;
            }
        }
    }
#if defined(_M_AMD64)
    architecture_ = Architecture::kX86_64;
#elif defined(_M_IX86)
    architecture_ = Architecture::kX86;
#elif defined(_M_ARM64)
    architecture_ = Architecture::kAArch64;
#elif defined(_M_ARM)
    architecture_ = Architecture::kArm;
#else
    architecture_ = Architecture::kUnknown;
#endif
    return architecture_ != Architecture::kUnknown;
}

bool WinDbgDebugSession::ensure_thread_handle(DWORD tid) {
    if (thread_handles_.count(tid)) {
        return true;
    }
    HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!thread) {
        return false;
    }
    thread_handles_.emplace(tid, thread);
    return true;
}

HANDLE WinDbgDebugSession::thread_handle(DWORD tid) const {
    auto it = thread_handles_.find(tid);
    if (it == thread_handles_.end()) {
        return nullptr;
    }
    return it->second;
}

void WinDbgDebugSession::remove_thread_handle(DWORD tid) {
    auto it = thread_handles_.find(tid);
    if (it != thread_handles_.end()) {
        CloseHandle(it->second);
        thread_handles_.erase(it);
    }
}

bool WinDbgDebugSession::wait_for_event(DebugEvent& event,
                                        std::chrono::milliseconds timeout) {
    if (!active_) {
        return false;
    }
    DEBUG_EVENT dbg_event;
    ZeroMemory(&dbg_event, sizeof(dbg_event));
    DWORD wait = WaitTimeout(timeout);
    BOOL ok;
#if defined(WAIT_TIMEOUT)
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
    ok = WaitForDebugEventEx(&dbg_event, wait);
#else
    ok = WaitForDebugEvent(&dbg_event, wait);
#endif
#else
    ok = WaitForDebugEvent(&dbg_event, wait);
#endif
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SEM_TIMEOUT) {
            return false;
        }
        return false;
    }

    event.pid = dbg_event.dwProcessId;
    event.tid = dbg_event.dwThreadId;
    event.address = 0;
    event.type = DebugEventType::kUnknown;

    switch (dbg_event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            event.type = DebugEventType::kProcessStart;
            if (dbg_event.u.CreateProcessInfo.hThread) {
                thread_handles_.emplace(dbg_event.dwThreadId,
                                        dbg_event.u.CreateProcessInfo.hThread);
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            event.type = DebugEventType::kProcessExit;
            event.exit_code = dbg_event.u.ExitProcess.dwExitCode;
            active_ = false;
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: {
            event.type = DebugEventType::kThreadStart;
            if (dbg_event.u.CreateThread.hThread) {
                thread_handles_.emplace(dbg_event.dwThreadId,
                                        dbg_event.u.CreateThread.hThread);
            }
            break;
        }
        case EXIT_THREAD_DEBUG_EVENT: {
            event.type = DebugEventType::kThreadExit;
            event.exit_code = dbg_event.u.ExitThread.dwExitCode;
            remove_thread_handle(dbg_event.dwThreadId);
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            const auto& info = dbg_event.u.Exception;
            event.address = reinterpret_cast<std::uint64_t>(
                info.ExceptionRecord.ExceptionAddress);
            event.signal_number = info.ExceptionRecord.ExceptionCode;
            if (info.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                event.type = DebugEventType::kBreakpoint;
                if (architecture_ == Architecture::kX86 ||
                    architecture_ == Architecture::kX86_64) {
                    event.address -= 1;
                }
            } else if (info.ExceptionRecord.ExceptionCode ==
                       EXCEPTION_SINGLE_STEP) {
                event.type = DebugEventType::kSingleStep;
            } else {
                event.type = DebugEventType::kSignal;
            }
            break;
        }
        default:
            event.type = DebugEventType::kUnknown;
            break;
    }

    last_event_ = dbg_event;
    has_pending_event_ = true;
    return true;
}

bool WinDbgDebugSession::resume(std::int64_t tid, std::int64_t /*signal*/) {
    if (!has_pending_event_) {
        return false;
    }
    DWORD thread_id = tid ? static_cast<DWORD>(tid) : last_event_.dwThreadId;
    if (!ensure_thread_handle(thread_id)) {
        return false;
    }
    BOOL ok = ContinueDebugEvent(last_event_.dwProcessId, thread_id, DBG_CONTINUE);
    has_pending_event_ = false;
    return ok == TRUE;
}

bool WinDbgDebugSession::single_step(std::int64_t tid, std::int64_t /*signal*/) {
    if (!has_pending_event_) {
        return false;
    }
    DWORD thread_id = tid ? static_cast<DWORD>(tid) : last_event_.dwThreadId;
    if (!ensure_thread_handle(thread_id)) {
        return false;
    }
    if (!apply_trap_flag(thread_id, true)) {
        return false;
    }
    BOOL ok = ContinueDebugEvent(last_event_.dwProcessId, thread_id, DBG_CONTINUE);
    has_pending_event_ = false;
    return ok == TRUE;
}

bool WinDbgDebugSession::apply_trap_flag(DWORD tid, bool enabled) {
    RegisterState state;
    if (!read_context(tid, state)) {
        return false;
    }
    bool updated = false;
    if (auto* regs = AsX86(state)) {
        if (enabled) {
            regs->eflags |= 0x100;
        } else {
            regs->eflags &= ~0x100u;
        }
        updated = true;
    } else if (auto* regs64 = AsX86_64(state)) {
        if (enabled) {
            regs64->rflags |= 0x100;
        } else {
            regs64->rflags &= ~0x100ull;
        }
        updated = true;
    }
    if (!updated) {
        return false;
    }
    return write_context(tid, state);
}

bool WinDbgDebugSession::read_memory(std::uint64_t address, void* buffer,
                                     std::size_t size) {
    SIZE_T read = 0;
    if (!ReadProcessMemory(process_handle_, reinterpret_cast<LPCVOID>(address),
                           buffer, size, &read)) {
        return false;
    }
    return read == size;
}

bool WinDbgDebugSession::write_memory(std::uint64_t address, const void* buffer,
                                      std::size_t size) {
    SIZE_T written = 0;
    if (!WriteProcessMemory(process_handle_, reinterpret_cast<LPVOID>(address),
                            buffer, size, &written)) {
        return false;
    }
    FlushInstructionCache(process_handle_, reinterpret_cast<LPCVOID>(address),
                          size);
    return written == size;
}

bool WinDbgDebugSession::read_bytes(std::uint64_t address, std::uint8_t* data,
                                    std::size_t size) {
    return read_memory(address, data, size);
}

bool WinDbgDebugSession::write_bytes(std::uint64_t address,
                                     const std::uint8_t* data,
                                     std::size_t size) {
    return write_memory(address, data, size);
}

std::vector<std::uint8_t> WinDbgDebugSession::breakpoint_opcode() const {
    switch (architecture_) {
        case Architecture::kX86:
        case Architecture::kX86_64:
            return {0xCC};
        case Architecture::kArm:
            return {0xFE, 0xDE};  // BKPT #0
        case Architecture::kAArch64:
            return {0x00, 0x00, 0x3D, 0xD4};  // BRK #0
        default:
            return {0xCC};
    }
}

bool WinDbgDebugSession::set_breakpoint(std::uint64_t address) {
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

bool WinDbgDebugSession::remove_breakpoint(std::uint64_t address) {
    auto it = breakpoints_.find(address);
    if (it == breakpoints_.end()) {
        return false;
    }
    if (it->second.installed) {
        if (!write_bytes(address, it->second.original.data(),
                         it->second.original.size())) {
            return false;
        }
    }
    breakpoints_.erase(it);
    return true;
}

void WinDbgDebugSession::restore_all_breakpoints() {
    for (auto& [address, info] : breakpoints_) {
        if (info.installed) {
            write_bytes(address, info.original.data(), info.original.size());
        }
    }
    breakpoints_.clear();
}

bool WinDbgDebugSession::read_context(DWORD tid, RegisterState& state) {
    if (!ensure_thread_handle(tid)) {
        return false;
    }
    HANDLE thread = thread_handle(tid);
    if (!thread) {
        return false;
    }
    switch (architecture_) {
        case Architecture::kX86_64: {
            CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(thread, &ctx)) {
                return false;
            }
            X86_64Registers regs{};
            regs.rax = ctx.Rax;
            regs.rbx = ctx.Rbx;
            regs.rcx = ctx.Rcx;
            regs.rdx = ctx.Rdx;
            regs.rsi = ctx.Rsi;
            regs.rdi = ctx.Rdi;
            regs.rbp = ctx.Rbp;
            regs.rsp = ctx.Rsp;
            regs.r8 = ctx.R8;
            regs.r9 = ctx.R9;
            regs.r10 = ctx.R10;
            regs.r11 = ctx.R11;
            regs.r12 = ctx.R12;
            regs.r13 = ctx.R13;
            regs.r14 = ctx.R14;
            regs.r15 = ctx.R15;
            regs.rip = ctx.Rip;
            regs.rflags = ctx.EFlags;
            state = regs;
            return true;
        }
        case Architecture::kX86: {
            WOW64_CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = WOW64_CONTEXT_ALL;
            if (!Wow64GetThreadContext(thread, &ctx)) {
                return false;
            }
            X86Registers regs{};
            regs.eax = ctx.Eax;
            regs.ebx = ctx.Ebx;
            regs.ecx = ctx.Ecx;
            regs.edx = ctx.Edx;
            regs.esi = ctx.Esi;
            regs.edi = ctx.Edi;
            regs.ebp = ctx.Ebp;
            regs.esp = ctx.Esp;
            regs.eip = ctx.Eip;
            regs.eflags = ctx.EFlags;
            state = regs;
            return true;
        }
        case Architecture::kAArch64: {
#ifdef CONTEXT_ARM64
            CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(thread, &ctx)) {
                return false;
            }
            AArch64Registers regs{};
            for (int i = 0; i < 31; ++i) {
                regs.x[i] = ctx.u.s.X[i];
            }
            regs.sp = ctx.Sp;
            regs.pc = ctx.Pc;
            regs.pstate = ctx.Cpsr;
            state = regs;
            return true;
#else
            return false;
#endif
        }
        case Architecture::kArm: {
#ifdef CONTEXT_ARM
            CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(thread, &ctx)) {
                return false;
            }
            ArmRegisters regs{};
            for (int i = 0; i < 16; ++i) {
                regs.r[i] = ctx.R[i];
            }
            regs.cpsr = ctx.Cpsr;
            state = regs;
            return true;
#else
            return false;
#endif
        }
        default:
            return false;
    }
}

bool WinDbgDebugSession::write_context(DWORD tid, const RegisterState& state) {
    if (!ensure_thread_handle(tid)) {
        return false;
    }
    HANDLE thread = thread_handle(tid);
    if (!thread) {
        return false;
    }
    switch (architecture_) {
        case Architecture::kX86_64: {
            CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(thread, &ctx)) {
                return false;
            }
            if (const auto* regs = AsX86_64(state)) {
                ctx.Rax = regs->rax;
                ctx.Rbx = regs->rbx;
                ctx.Rcx = regs->rcx;
                ctx.Rdx = regs->rdx;
                ctx.Rsi = regs->rsi;
                ctx.Rdi = regs->rdi;
                ctx.Rbp = regs->rbp;
                ctx.Rsp = regs->rsp;
                ctx.R8 = regs->r8;
                ctx.R9 = regs->r9;
                ctx.R10 = regs->r10;
                ctx.R11 = regs->r11;
                ctx.R12 = regs->r12;
                ctx.R13 = regs->r13;
                ctx.R14 = regs->r14;
                ctx.R15 = regs->r15;
                ctx.Rip = regs->rip;
                ctx.EFlags = static_cast<DWORD>(regs->rflags);
                return SetThreadContext(thread, &ctx) == TRUE;
            }
            return false;
        }
        case Architecture::kX86: {
            WOW64_CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = WOW64_CONTEXT_ALL;
            if (!Wow64GetThreadContext(thread, &ctx)) {
                return false;
            }
            if (const auto* regs = AsX86(state)) {
                ctx.Eax = regs->eax;
                ctx.Ebx = regs->ebx;
                ctx.Ecx = regs->ecx;
                ctx.Edx = regs->edx;
                ctx.Esi = regs->esi;
                ctx.Edi = regs->edi;
                ctx.Ebp = regs->ebp;
                ctx.Esp = regs->esp;
                ctx.Eip = regs->eip;
                ctx.EFlags = regs->eflags;
                return Wow64SetThreadContext(thread, &ctx) == TRUE;
            }
            return false;
        }
        case Architecture::kAArch64: {
#ifdef CONTEXT_ARM64
            CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(thread, &ctx)) {
                return false;
            }
            if (const auto* regs = AsAArch64(state)) {
                for (int i = 0; i < 31; ++i) {
                    ctx.u.s.X[i] = regs->x[i];
                }
                ctx.Sp = regs->sp;
                ctx.Pc = regs->pc;
                ctx.Cpsr = static_cast<DWORD>(regs->pstate);
                return SetThreadContext(thread, &ctx) == TRUE;
            }
            return false;
#else
            return false;
#endif
        }
        case Architecture::kArm: {
#ifdef CONTEXT_ARM
            CONTEXT ctx;
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(thread, &ctx)) {
                return false;
            }
            if (const auto* regs = AsArm(state)) {
                for (int i = 0; i < 16; ++i) {
                    ctx.R[i] = regs->r[i];
                }
                ctx.Cpsr = regs->cpsr;
                return SetThreadContext(thread, &ctx) == TRUE;
            }
            return false;
#else
            return false;
#endif
        }
        default:
            return false;
    }
}

bool WinDbgDebugSession::get_thread_registers(std::int64_t tid,
                                               RegisterState& state) {
    return read_context(static_cast<DWORD>(tid), state);
}

bool WinDbgDebugSession::set_thread_registers(
    std::int64_t tid, const RegisterState& state) {
    return write_context(static_cast<DWORD>(tid), state);
}

Architecture WinDbgDebugSession::architecture() const { return architecture_; }

bool WinDbgDebugSession::terminate() {
    if (!process_handle_) {
        return false;
    }
    if (!TerminateProcess(process_handle_, 0)) {
        return false;
    }
    active_ = false;
    return true;
}

bool WinDbgDebugSession::detach() {
    if (!attached_) {
        if (!DebugActiveProcessStop(pid_)) {
            return false;
        }
    } else {
        DebugActiveProcessStop(pid_);
    }
    active_ = false;
    return true;
}

}  // namespace dynscanner

