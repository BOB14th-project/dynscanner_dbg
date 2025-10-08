#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "dynscanner/registers.hpp"

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
    kSingleStep,
    kSignal,
    kUnknown
};

struct DebugEvent {
    DebugEventType type{DebugEventType::kNone};
    std::int64_t pid{0};
    std::int64_t tid{0};
    std::int64_t signal_number{0};
    std::int64_t exit_code{0};
    std::uint64_t address{0};
};

class DebugSession {
public:
    virtual ~DebugSession() = default;

    DebugSession(const DebugSession&) = delete;
    DebugSession& operator=(const DebugSession&) = delete;

    virtual bool wait_for_event(DebugEvent& event,
                                std::chrono::milliseconds timeout) = 0;
    virtual bool resume(std::int64_t tid, std::int64_t signal = 0) = 0;
    virtual bool single_step(std::int64_t tid, std::int64_t signal = 0) = 0;
    virtual bool read_memory(std::uint64_t address, void* buffer,
                             std::size_t size) = 0;
    virtual bool write_memory(std::uint64_t address, const void* buffer,
                              std::size_t size) = 0;
    virtual bool set_breakpoint(std::uint64_t address) = 0;
    virtual bool remove_breakpoint(std::uint64_t address) = 0;
    virtual bool get_thread_registers(std::int64_t tid,
                                      RegisterState& state) = 0;
    virtual bool set_thread_registers(std::int64_t tid,
                                      const RegisterState& state) = 0;
    virtual Architecture architecture() const = 0;
    virtual bool terminate() = 0;
    virtual bool detach() = 0;

    static std::unique_ptr<DebugSession> Launch(const LaunchOptions& options,
                                                std::string* error);
    static std::unique_ptr<DebugSession> Attach(std::int64_t pid,
                                                std::string* error);

protected:
    DebugSession() = default;
};

}  // namespace dynscanner

