#include "dynscanner/analyzer.hpp"
#include "dynscanner/debug_session.hpp"

#include <chrono>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

struct CliOptions {
    dynscanner::LaunchOptions launch;
    std::optional<std::int64_t> attach_pid;
    std::vector<std::uint64_t> breakpoints;
    dynscanner::AnalyzerConfig analyzer_config;
    std::chrono::milliseconds event_timeout{1000};
};

void PrintUsage() {
    std::cout << "사용법: dynscanner_cli [--attach <pid> | --target <실행파일>]" << '\n'
              << "                [--arg <인자>]..." << '\n'
              << "                [--breakpoint <주소>]..." << '\n'
              << "                [--code-window <크기>]" << '\n'
              << "                [--stack-window <크기>]" << '\n'
              << "                [--no-code-snapshot]" << '\n'
              << "                [--no-stack-snapshot]" << '\n'
              << "                [--env KEY=VALUE]..." << '\n'
              << "                [--cwd <디렉터리>]" << '\n';
}

bool ParseU64(std::string_view token, std::uint64_t* value) {
    if (token.empty()) {
        return false;
    }
    std::string s(token);
    std::size_t idx = 0;
    try {
        *value = std::stoull(s, &idx, 0);
    } catch (...) {
        return false;
    }
    return idx == s.size();
}

bool ParseOptions(int argc, char** argv, CliOptions* options) {
    if (argc < 2) {
        PrintUsage();
        return false;
    }

    for (int i = 1; i < argc; ++i) {
        std::string_view token(argv[i]);
        if (token == "--target" && i + 1 < argc) {
            options->launch.executable = argv[++i];
            continue;
        }
        if (token == "--arg" && i + 1 < argc) {
            options->launch.arguments.emplace_back(argv[++i]);
            continue;
        }
        if (token == "--breakpoint" && i + 1 < argc) {
            std::uint64_t addr = 0;
            if (!ParseU64(argv[i + 1], &addr)) {
                std::cerr << "잘못된 주소 형식: " << argv[i + 1] << '\n';
                return false;
            }
            options->breakpoints.push_back(addr);
            ++i;
            continue;
        }
        if (token == "--code-window" && i + 1 < argc) {
            std::uint64_t size = 0;
            if (!ParseU64(argv[i + 1], &size)) {
                std::cerr << "잘못된 크기: " << argv[i + 1] << '\n';
                return false;
            }
            options->analyzer_config.code_window_size = static_cast<std::size_t>(size);
            ++i;
            continue;
        }
        if (token == "--stack-window" && i + 1 < argc) {
            std::uint64_t size = 0;
            if (!ParseU64(argv[i + 1], &size)) {
                std::cerr << "잘못된 크기: " << argv[i + 1] << '\n';
                return false;
            }
            options->analyzer_config.stack_window_size = static_cast<std::size_t>(size);
            ++i;
            continue;
        }
        if (token == "--no-code-snapshot") {
            options->analyzer_config.capture_code = false;
            continue;
        }
        if (token == "--no-stack-snapshot") {
            options->analyzer_config.capture_stack = false;
            continue;
        }
        if (token == "--env" && i + 1 < argc) {
            std::string env_pair(argv[++i]);
            auto pos = env_pair.find('=');
            if (pos == std::string::npos || pos == 0) {
                std::cerr << "환경 변수 형식이 잘못되었습니다: " << env_pair << '\n';
                return false;
            }
            options->launch.environment.emplace(env_pair.substr(0, pos),
                                                env_pair.substr(pos + 1));
            continue;
        }
        if (token == "--cwd" && i + 1 < argc) {
            options->launch.working_directory = std::string(argv[++i]);
            continue;
        }
        if (token == "--attach" && i + 1 < argc) {
            std::uint64_t pid = 0;
            if (!ParseU64(argv[i + 1], &pid)) {
                std::cerr << "잘못된 PID: " << argv[i + 1] << '\n';
                return false;
            }
            options->attach_pid = static_cast<std::int64_t>(pid);
            ++i;
            continue;
        }
        if (token == "--") {
            for (int j = i + 1; j < argc; ++j) {
                options->launch.arguments.emplace_back(argv[j]);
            }
            break;
        }

        std::cerr << "알 수 없는 옵션: " << token << '\n';
        PrintUsage();
        return false;
    }

    if (!options->attach_pid && options->launch.executable.empty()) {
        std::cerr << "--target 또는 --attach 중 하나는 반드시 지정해야 합니다." << '\n';
        return false;
    }
    if (options->attach_pid && !options->launch.executable.empty()) {
        std::cerr << "--target과 --attach는 동시에 사용할 수 없습니다." << '\n';
        return false;
    }
    return true;
}

std::string EventToString(const dynscanner::DebugEvent& event) {
    std::ostringstream oss;
    oss << "pid=" << event.pid << ", tid=" << event.tid << ", ";
    switch (event.type) {
        case dynscanner::DebugEventType::kProcessStart:
            oss << "프로세스 시작";
            break;
        case dynscanner::DebugEventType::kProcessExit:
            oss << "프로세스 종료 (코드=" << event.exit_code << ")";
            break;
        case dynscanner::DebugEventType::kBreakpoint:
            oss << "브레이크포인트 (주소=0x" << std::hex << event.address << ")";
            break;
        case dynscanner::DebugEventType::kSingleStep:
            oss << "단일 스텝 완료";
            break;
        case dynscanner::DebugEventType::kSignal:
            oss << "시그널 수신 (" << event.signal_number << ")";
            break;
        case dynscanner::DebugEventType::kThreadStart:
            oss << "스레드 시작";
            break;
        case dynscanner::DebugEventType::kThreadExit:
            oss << "스레드 종료";
            break;
        default:
            oss << "알 수 없는 이벤트";
            break;
    }
    return oss.str();
}

void PrintDetections(const std::vector<dynscanner::Detection>& detections) {
    for (const auto& detection : detections) {
        auto time = std::chrono::duration_cast<std::chrono::milliseconds>(
            detection.timestamp.time_since_epoch());
        std::cout << "[탐지] rule=" << detection.rule_name << ", address=0x"
                  << std::hex << detection.address << std::dec
                  << ", time=" << time.count() << "ms"
                  << " => " << detection.description << '\n';
    }
}

std::vector<std::uint8_t> CaptureWindow(dynscanner::DebugSession& session,
                                        std::uint64_t address,
                                        std::size_t size) {
    std::vector<std::uint8_t> buffer;
    if (size == 0) {
        return buffer;
    }
    buffer.resize(size);
    if (!session.read_memory(address, buffer.data(), buffer.size())) {
        buffer.clear();
    }
    return buffer;
}

}  // namespace

int main(int argc, char** argv) {
    CliOptions options;
    if (!ParseOptions(argc, argv, &options)) {
        return 1;
    }

    std::string error;
    std::unique_ptr<dynscanner::DebugSession> session;
    if (options.attach_pid) {
        session = dynscanner::DebugSession::Attach(*options.attach_pid, &error);
    } else {
        session = dynscanner::DebugSession::Launch(options.launch, &error);
    }

    if (!session) {
        std::cerr << "디버그 세션 생성 실패: " << error << '\n';
        return 1;
    }

    dynscanner::Analyzer analyzer(options.analyzer_config);
    std::unordered_map<std::int64_t, std::uint64_t> pending_breakpoints;

    bool running = true;
    while (running) {
        dynscanner::DebugEvent event;
        if (!session->wait_for_event(event, options.event_timeout)) {
            continue;
        }

        std::cout << EventToString(event) << '\n';

        switch (event.type) {
            case dynscanner::DebugEventType::kProcessStart: {
                for (auto address : options.breakpoints) {
                    if (!session->set_breakpoint(address)) {
                        std::cerr << "브레이크포인트 설정 실패: 0x" << std::hex
                                  << address << std::dec << '\n';
                    }
                }
                session->resume(event.tid);
                break;
            }
            case dynscanner::DebugEventType::kBreakpoint: {
                dynscanner::RegisterState state;
                if (!session->get_thread_registers(event.tid, state)) {
                    std::cerr << "레지스터 읽기 실패" << '\n';
                    session->resume(event.tid);
                    break;
                }

                const auto* regs64 = dynscanner::AsX86_64(state);
                if (regs64) {
                    const std::uint64_t bp_address = event.address;
                    if (!session->remove_breakpoint(bp_address)) {
                        std::cerr << "브레이크포인트 복원 실패" << '\n';
                        session->resume(event.tid);
                        break;
                    }

                    dynscanner::RegisterState patched_state = state;
                    auto* mutable_regs = dynscanner::AsX86_64(patched_state);
                    mutable_regs->rip = bp_address;
                    if (!session->set_thread_registers(event.tid, patched_state)) {
                        std::cerr << "문맥 복원 실패" << '\n';
                        session->resume(event.tid);
                        break;
                    }

                    dynscanner::Snapshot snapshot;
                    snapshot.event = event;
                    snapshot.registers = patched_state;
                    snapshot.timestamp = std::chrono::steady_clock::now();
                    if (options.analyzer_config.capture_code) {
                        snapshot.code_window = CaptureWindow(
                            *session, bp_address,
                            options.analyzer_config.code_window_size);
                    }
                    if (options.analyzer_config.capture_stack) {
                        snapshot.stack_window = CaptureWindow(
                            *session, mutable_regs->rsp,
                            options.analyzer_config.stack_window_size);
                    }
                    auto detections = analyzer.ProcessSnapshot(snapshot);
                    PrintDetections(detections);

                    pending_breakpoints[event.tid] = bp_address;
                    if (!session->single_step(event.tid)) {
                        std::cerr << "단일 스텝 실패" << '\n';
                        session->resume(event.tid);
                        pending_breakpoints.erase(event.tid);
                        break;
                    }
                } else {
                    session->resume(event.tid);
                }
                break;
            }
            case dynscanner::DebugEventType::kSingleStep: {
                auto it = pending_breakpoints.find(event.tid);
                if (it != pending_breakpoints.end()) {
                    if (!session->set_breakpoint(it->second)) {
                        std::cerr << "브레이크포인트 재설치 실패" << '\n';
                    }
                    pending_breakpoints.erase(it);
                }
                session->resume(event.tid);
                break;
            }
            case dynscanner::DebugEventType::kSignal: {
                if (event.signal_number == SIGKILL) {
                    running = false;
                } else {
                    session->resume(event.tid, event.signal_number);
                }
                break;
            }
            case dynscanner::DebugEventType::kProcessExit: {
                running = false;
                break;
            }
            default:
                session->resume(event.tid);
                break;
        }
    }

    return 0;
}

