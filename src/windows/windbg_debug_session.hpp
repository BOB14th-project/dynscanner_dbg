#pragma once

#include "dynscanner/debug_session.hpp"

#include <windows.h>

#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dynscanner {

class WinDbgDebugSession : public DebugSession {
public:
    static std::unique_ptr<WinDbgDebugSession> Launch(const LaunchOptions& options,
                                                      std::string* error);
    static std::unique_ptr<WinDbgDebugSession> Attach(DWORD pid, std::string* error);

    ~WinDbgDebugSession() override;

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
    WinDbgDebugSession(HANDLE process, DWORD pid, bool attached);

    bool initialize(std::string* error);
    bool update_architecture();
    bool ensure_thread_handle(DWORD tid);
    HANDLE thread_handle(DWORD tid) const;
    void remove_thread_handle(DWORD tid);
    bool apply_trap_flag(DWORD tid, bool enabled);
    bool read_context(DWORD tid, RegisterState& state);
    bool write_context(DWORD tid, const RegisterState& state);
    std::vector<std::uint8_t> breakpoint_opcode() const;
    bool write_bytes(std::uint64_t address, const std::uint8_t* data,
                     std::size_t size);
    bool read_bytes(std::uint64_t address, std::uint8_t* data,
                    std::size_t size);
    void restore_all_breakpoints();

    struct BreakpointInfo {
        std::vector<std::uint8_t> original;
        bool installed{false};
    };

    HANDLE process_handle_{nullptr};
    DWORD pid_{0};
    Architecture architecture_{Architecture::kUnknown};
    bool active_{false};
    bool attached_{false};
    DEBUG_EVENT last_event_{};
    bool has_pending_event_{false};
    std::unordered_map<DWORD, HANDLE> thread_handles_;
    std::unordered_map<std::uint64_t, BreakpointInfo> breakpoints_;
};

}  // namespace dynscanner

