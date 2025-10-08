#include "dynscanner/debug_session.hpp"

#include <system_error>

#if defined(__linux__)
#include "linux/ptrace_debug_session.hpp"
#elif defined(_WIN32)
#include "windows/windbg_debug_session.hpp"
#elif defined(__APPLE__)
#include "macos/mach_debug_session.hpp"
#endif

namespace dynscanner {

std::unique_ptr<DebugSession> DebugSession::Launch(const LaunchOptions& options,
                                                   std::string* error) {
#if defined(__linux__)
    return PtraceDebugSession::Launch(options, error);
#elif defined(_WIN32)
    return WinDbgDebugSession::Launch(options, error);
#elif defined(__APPLE__)
    return MachDebugSession::Launch(options, error);
#else
    if (error) {
        *error = "현재 플랫폼에서는 디버그 세션 생성이 지원되지 않습니다.";
    }
    return nullptr;
#endif
}

std::unique_ptr<DebugSession> DebugSession::Attach(std::int64_t pid,
                                                   std::string* error) {
#if defined(__linux__)
    return PtraceDebugSession::Attach(static_cast<pid_t>(pid), error);
#elif defined(_WIN32)
    return WinDbgDebugSession::Attach(static_cast<DWORD>(pid), error);
#elif defined(__APPLE__)
    return MachDebugSession::Attach(static_cast<pid_t>(pid), error);
#else
    if (error) {
        *error = "현재 플랫폼에서는 디버그 세션 attach 기능이 지원되지 않습니다.";
    }
    return nullptr;
#endif
}

}  // namespace dynscanner

