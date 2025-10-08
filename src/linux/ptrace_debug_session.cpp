#include "linux/ptrace_debug_session.hpp"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#ifndef __WALL
#define __WALL 0
#endif

namespace dynscanner {
namespace {

std::vector<char*> BuildExecArguments(const LaunchOptions& options,
                                      std::vector<std::string>* storage) {
    storage->clear();
    storage->push_back(options.executable);
    for (const auto& arg : options.arguments) {
        storage->push_back(arg);
    }
    std::vector<char*> argv;
    argv.reserve(storage->size() + 1);
    for (auto& value : *storage) {
        argv.push_back(value.data());
    }
    argv.push_back(nullptr);
    return argv;
}

}  // namespace

std::unique_ptr<PtraceDebugSession> PtraceDebugSession::Launch(
    const LaunchOptions& options, std::string* error) {
    if (options.executable.empty()) {
        if (error) {
            *error = "실행 파일 경로가 비어 있습니다.";
        }
        return nullptr;
    }

    pid_t child = fork();
    if (child < 0) {
        if (error) {
            *error = std::string("fork 실패: ") + strerror(errno);
        }
        return nullptr;
    }

    if (child == 0) {
        if (!options.working_directory) {
            // keep current working directory
        } else if (chdir(options.working_directory->c_str()) != 0) {
            std::cerr << "작업 디렉터리 변경 실패: " << strerror(errno) << std::endl;
            _exit(1);
        }

        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
            std::cerr << "PTRACE_TRACEME 실패: " << strerror(errno) << std::endl;
            _exit(1);
        }

        raise(SIGSTOP);

        std::vector<std::string> storage;
        storage.reserve(1 + options.arguments.size());
        auto argv = BuildExecArguments(options, &storage);
        execvp(options.executable.c_str(), argv.data());
        std::cerr << "execvp 실패: " << strerror(errno) << std::endl;
        _exit(1);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        if (error) {
            *error = std::string("waitpid 실패: ") + strerror(errno);
        }
        kill(child, SIGKILL);
        return nullptr;
    }

    if (!WIFSTOPPED(status)) {
        if (error) {
            *error = "자식 프로세스가 추적 시작 전에 종료되었습니다.";
        }
        kill(child, SIGKILL);
        return nullptr;
    }

    auto session = std::unique_ptr<PtraceDebugSession>(new PtraceDebugSession(child));
    session->active_ = true;

    if (error) {
        error->clear();
    }
    return session;
}

PtraceDebugSession::PtraceDebugSession(pid_t pid) : pid_(pid) {}

PtraceDebugSession::~PtraceDebugSession() {
    if (active_) {
        terminate();
    }
}

bool PtraceDebugSession::wait_for_event(DebugEvent& event,
                                        std::chrono::milliseconds timeout) {
    if (!active_) {
        return false;
    }

    const bool infinite_wait = timeout.count() < 0;
    const auto deadline =
        infinite_wait ? std::chrono::steady_clock::time_point::max()
                       : std::chrono::steady_clock::now() + timeout;

    while (true) {
        int status = 0;
        pid_t result = waitpid(pid_, &status, WNOHANG | __WALL | WUNTRACED | WCONTINUED);
        if (result == 0) {
            if (!infinite_wait && std::chrono::steady_clock::now() >= deadline) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }

        if (!translate_wait_status(status, event)) {
            return false;
        }
        event.pid = pid_;
        event.tid = pid_;
        return true;
    }
}

bool PtraceDebugSession::continue_event(std::int64_t tid, std::int64_t signal) {
    if (!active_) {
        return false;
    }
    if (ptrace(PTRACE_CONT, static_cast<pid_t>(tid), nullptr,
               reinterpret_cast<void*>(signal)) != 0) {
        return false;
    }
    return true;
}

bool PtraceDebugSession::terminate() {
    if (!active_) {
        return true;
    }

    if (kill(pid_, SIGKILL) != 0) {
        return false;
    }

    int status = 0;
    waitpid(pid_, &status, 0);
    active_ = false;
    return true;
}

bool PtraceDebugSession::translate_wait_status(int status, DebugEvent& event) {
    if (WIFEXITED(status)) {
        event.type = DebugEventType::kProcessExit;
        event.exit_code = WEXITSTATUS(status);
        active_ = false;
        return true;
    }
    if (WIFSIGNALED(status)) {
        event.type = DebugEventType::kSignal;
        event.signal_number = WTERMSIG(status);
        active_ = false;
        return true;
    }
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        if (initial_stop_pending_ && sig == SIGSTOP) {
            event.type = DebugEventType::kProcessStart;
            event.signal_number = sig;
            initial_stop_pending_ = false;
            return true;
        }
        if (sig == SIGTRAP) {
            event.type = DebugEventType::kBreakpoint;
            event.signal_number = sig;
        } else {
            event.type = DebugEventType::kSignal;
            event.signal_number = sig;
        }
        return true;
    }
    event.type = DebugEventType::kUnknown;
    return true;
}

}  // namespace dynscanner

