#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dynscanner/debug_session.hpp"
#include "dynscanner/registers.hpp"

namespace dynscanner {

struct AnalyzerConfig {
    std::size_t code_window_size{64};
    std::size_t stack_window_size{128};
    bool capture_code{true};
    bool capture_stack{true};
};

struct Snapshot {
    DebugEvent event;
    RegisterState registers;
    std::vector<std::uint8_t> code_window;
    std::vector<std::uint8_t> stack_window;
    std::chrono::steady_clock::time_point timestamp;
};

struct Detection {
    std::string rule_name;
    std::string description;
    std::uint64_t address{0};
    std::chrono::steady_clock::time_point timestamp{};
};

class CryptoRule {
public:
    virtual ~CryptoRule() = default;
    virtual std::string name() const = 0;
    virtual void Evaluate(const Snapshot& snapshot,
                          std::vector<Detection>& out) = 0;
};

class Analyzer {
public:
    explicit Analyzer(AnalyzerConfig config = {});

    void RegisterRule(std::unique_ptr<CryptoRule> rule);

    std::vector<Detection> ProcessSnapshot(const Snapshot& snapshot);

    const std::vector<Detection>& detections() const { return detections_; }

private:
    AnalyzerConfig config_{};
    std::vector<std::unique_ptr<CryptoRule>> rules_;
    std::vector<Detection> detections_;
};

}  // namespace dynscanner

