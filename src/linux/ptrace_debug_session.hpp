#pragma once

#include "dynscanner/debug_session.hpp"
#include "dynscanner/registers.hpp"

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
    static std::unique_ptr<PtraceDebugSession> Attach(pid_t pid,
                                                      std::string* error);

    ~PtraceDebugSession() override;

    bool wait_for_event(DebugEvent& event,
                        std::chrono::milliseconds timeout) override;
    bool resume(std::int64_t tid, std::int64_t signal) override;
    bool single_step(std::int64_t tid, std::int64_t signal) override;
    bool read_memory(std::uint64_t address, void* buffer,
                     std::size_t size) override;
    bool write_memory(std::uint64_t address, const void* buffer,
                      std::size_t size) override;
    bool set_breakpoint(std::uint64_t address) override;
    bool remove_breakpoint(std::uint64_t address) override;
    bool get_thread_registers(std::int64_t tid, RegisterState& state) override;
    bool set_thread_registers(std::int64_t tid, const RegisterState& state) override;
    Architecture architecture() const override;
    bool terminate() override;
    bool detach() override;

private:
    explicit PtraceDebugSession(pid_t pid);

    bool initialize_after_stop(pid_t tid, int status, std::string* error);
    bool translate_wait_status(pid_t tid, int status, DebugEvent& event);
    bool fetch_program_counter(pid_t tid, std::uint64_t& pc);
    bool apply_registers(pid_t tid, const RegisterState& state);
    bool fill_registers(pid_t tid, RegisterState& state);
    void restore_all_breakpoints();

    struct BreakpointInfo {
        std::uint64_t word_address;
        unsigned long original_data;
        std::uint8_t byte_offset;
    };

    pid_t pid_{-1};
    bool active_{false};
    bool initial_stop_pending_{true};
    Architecture architecture_{Architecture::kUnknown};
    std::unordered_map<std::uint64_t, BreakpointInfo> breakpoints_;
    std::unordered_map<pid_t, bool> single_step_threads_;
};

}  // namespace dynscanner

