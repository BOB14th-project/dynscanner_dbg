#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dynscanner {

struct LaunchOptions {
    std::string executable;
    std::vector<std::string> arguments;
    std::optional<std::string> working_directory;
    std::map<std::string, std::string> environment;
};

enum class DebugEventType {
    kNone,
    kProcessStart,
    kProcessExit,
    kThreadStart,
    kThreadExit,
    kBreakpoint,
    kSignal,
    kUnknown
};

struct DebugEvent {
    DebugEventType type{DebugEventType::kNone};
    std::int64_t pid{0};
    std::int64_t tid{0};
    std::int64_t signal_number{0};
    std::int64_t exit_code{0};
};

class DebugSession {
public:
    virtual ~DebugSession() = default;

    DebugSession(const DebugSession&) = delete;
    DebugSession& operator=(const DebugSession&) = delete;

    virtual bool wait_for_event(DebugEvent& event,
                                std::chrono::milliseconds timeout) = 0;
    virtual bool continue_event(std::int64_t tid, std::int64_t signal = 0) = 0;
    virtual bool terminate() = 0;

    static std::unique_ptr<DebugSession> Launch(const LaunchOptions& options,
                                                std::string* error);

protected:
    DebugSession() = default;
};

}  // namespace dynscanner

