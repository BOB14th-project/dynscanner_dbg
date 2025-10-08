#pragma once

#include "dynscanner/debug_session.hpp"

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <string>

namespace dynscanner {

class PtraceDebugSession : public DebugSession {
public:
    static std::unique_ptr<PtraceDebugSession> Launch(const LaunchOptions& options,
                                                      std::string* error);

    ~PtraceDebugSession() override;

    bool wait_for_event(DebugEvent& event,
                        std::chrono::milliseconds timeout) override;
    bool continue_event(std::int64_t tid, std::int64_t signal) override;
    bool terminate() override;

private:
    explicit PtraceDebugSession(pid_t pid);

    bool translate_wait_status(int status, DebugEvent& event);

    pid_t pid_{-1};
    bool active_{false};
    bool initial_stop_pending_{true};
};

}  // namespace dynscanner

