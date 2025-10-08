#include "dynscanner/debug_session.hpp"

#include <chrono>
#include <csignal>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void PrintUsage() {
    std::cout << "사용법: dynscanner_cli --target <실행파일> [-- <인자...>]\n";
}

bool ParseArguments(int argc, char** argv, dynscanner::LaunchOptions* options) {
    if (argc < 3) {
        PrintUsage();
        return false;
    }

    for (int i = 1; i < argc; ++i) {
        std::string_view token(argv[i]);
        if (token == "--target" && i + 1 < argc) {
            options->executable = argv[++i];
            continue;
        }
        if (token == "--") {
            for (int j = i + 1; j < argc; ++j) {
                options->arguments.emplace_back(argv[j]);
            }
            break;
        }
        std::cerr << "알 수 없는 인자: " << token << "\n";
        return false;
    }

    if (options->executable.empty()) {
        std::cerr << "--target 옵션은 필수입니다.\n";
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
            oss << "브레이크포인트/트랩";
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

}  // namespace

int main(int argc, char** argv) {
    dynscanner::LaunchOptions options;
    if (!ParseArguments(argc, argv, &options)) {
        return 1;
    }

    std::string error;
    auto session = dynscanner::DebugSession::Launch(options, &error);
    if (!session) {
        std::cerr << "디버그 세션 생성 실패: " << error << "\n";
        return 1;
    }

    while (true) {
        dynscanner::DebugEvent event;
        if (!session->wait_for_event(event, std::chrono::milliseconds(1000))) {
            continue;
        }

        std::cout << EventToString(event) << std::endl;

        if (event.type == dynscanner::DebugEventType::kProcessExit ||
            event.type == dynscanner::DebugEventType::kSignal &&
                event.signal_number == SIGKILL) {
            break;
        }

        if (!session->continue_event(event.tid, 0)) {
            std::cerr << "프로세스 계속 실행 실패" << std::endl;
            break;
        }
    }

    return 0;
}

