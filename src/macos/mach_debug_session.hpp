#pragma once

#include "dynscanner/debug_session.hpp"

#include <mach/mach.h>
#include <mach/mach_vm.h>

#include <array>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace dynscanner {

class MachDebugSession : public DebugSession {
public:
    static std::unique_ptr<MachDebugSession> Launch(const LaunchOptions& options,
                                                    std::string* error);
    static std::unique_ptr<MachDebugSession> Attach(pid_t pid,
                                                    std::string* error);

    ~MachDebugSession() override;

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

    kern_return_t HandleException(mach_port_t thread, mach_port_t task,
                                  exception_type_t exception,
                                  const mach_exception_data_type_t* code,
                                  mach_msg_type_number_t code_count,
                                  int* flavor, mach_msg_type_number_t* state_count,
                                  natural_t* state);

private:
    MachDebugSession(task_t task, pid_t pid, bool attached);

    bool initialize(std::string* error);
    bool configure_exception_port(std::string* error);
    bool refresh_threads();
    thread_act_t thread_from_id(std::int64_t tid) const;
    bool read_thread_state(thread_act_t thread, RegisterState& state);
    bool write_thread_state(thread_act_t thread, const RegisterState& state);
    std::vector<std::uint8_t> breakpoint_opcode() const;
    bool write_bytes(std::uint64_t address, const std::uint8_t* data,
                     std::size_t size);
    bool read_bytes(std::uint64_t address, std::uint8_t* data,
                    std::size_t size);
    bool send_pending_reply();
    void restore_all_breakpoints();

    struct BreakpointInfo {
        std::vector<std::uint8_t> original;
        bool installed{false};
    };

    struct PendingException {
        mach_msg_header_t request_header{};
        mach_msg_header_t reply_header{};
        NDR_record_t ndr{};
        kern_return_t ret{KERN_SUCCESS};
        int flavor{0};
        mach_msg_type_number_t state_count{0};
        std::array<natural_t, THREAD_STATE_MAX> state{};
        mach_port_t thread_port{MACH_PORT_NULL};
        mach_port_t task_port{MACH_PORT_NULL};
        exception_type_t exception{0};
        mach_exception_data_type_t code[2]{};
        mach_msg_type_number_t code_count{0};
        DebugEvent event{};
        bool valid{false};
    };

    task_t task_{MACH_PORT_NULL};
    pid_t pid_{0};
    bool attached_{false};
    bool active_{false};
    Architecture architecture_{Architecture::kUnknown};
    mach_port_t exception_port_{MACH_PORT_NULL};
    PendingException pending_{};
    std::unordered_map<std::int64_t, thread_act_t> threads_;
    std::unordered_map<std::uint64_t, BreakpointInfo> breakpoints_;
};

}  // namespace dynscanner

extern "C" kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t code_count, int* flavor,
    mach_msg_type_number_t* state_count, natural_t* state);

