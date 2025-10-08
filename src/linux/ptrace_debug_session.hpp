#pragma once

#include "dynscanner/debug_session.hpp"

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace dynscanner {

class PtraceDebugSession : public DebugSession {
public:
    static std::unique_ptr<PtraceDebugSession> Launch(const LaunchOptions& options,
                                                      std::string* error);

    ~PtraceDebugSession() override;

    bool wait_for_event(DebugEvent& event,
                        std::chrono::milliseconds timeout) override;
    bool continue_event(std::int64_t tid, std::int64_t signal) override;
    bool read_memory(std::uint64_t address, void* buffer,
                     std::size_t size) override;
    bool write_memory(std::uint64_t address, const void* buffer,
                      std::size_t size) override;
    bool set_breakpoint(std::uint64_t address) override;
    bool remove_breakpoint(std::uint64_t address) override;
    bool terminate() override;

private:
    explicit PtraceDebugSession(pid_t pid);

    bool translate_wait_status(int status, DebugEvent& event);

    struct BreakpointInfo {
        std::uint64_t word_address;
        unsigned long original_data;
        std::uint8_t byte_offset;
    };

    pid_t pid_{-1};
    bool active_{false};
    bool initial_stop_pending_{true};
    std::unordered_map<std::uint64_t, BreakpointInfo> breakpoints_;
};

}  // namespace dynscanner

