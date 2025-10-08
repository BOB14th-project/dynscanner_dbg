#include "dynscanner/debug_session.hpp"

#include <system_error>

#if defined(__linux__)
#include "linux/ptrace_debug_session.hpp"
#endif

namespace dynscanner {

std::unique_ptr<DebugSession> DebugSession::Launch(const LaunchOptions& options,
                                                   std::string* error) {
#if defined(__linux__)
    return PtraceDebugSession::Launch(options, error);
#else
    if (error) {
        *error = "현재 플랫폼에서는 디버그 세션 생성이 지원되지 않습니다.";
    }
    return nullptr;
#endif
}

}  // namespace dynscanner

