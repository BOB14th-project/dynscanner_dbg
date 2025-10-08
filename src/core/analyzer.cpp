#include "dynscanner/analyzer.hpp"

#include <algorithm>
#include <array>
#include <sstream>
#include <string>
#include <utility>

namespace dynscanner {
namespace {

constexpr std::array<std::uint8_t, 16> kChaChaSigma = {
    0x65, 0x78, 0x70, 0x61,  // "expa"
    0x6E, 0x64, 0x20, 0x33,  // "nd 3"
    0x32, 0x2D, 0x62, 0x79,  // "2-by"
    0x74, 0x65, 0x20, 0x6B   // "te k"
};

class BlockCopyHeuristicRule : public CryptoRule {
public:
    std::string name() const override { return "BlockCopyHeuristic"; }

    void Evaluate(const Snapshot& snapshot,
                  std::vector<Detection>& out) override {
        const auto* regs64 = AsX86_64(snapshot.registers);
        if (!regs64) {
            return;
        }

        const std::uint64_t candidates[] = {regs64->rcx, regs64->rdx, regs64->r8,
                                            regs64->r9};
        const auto it = std::max_element(std::begin(candidates),
                                         std::end(candidates));
        if (*it < 16) {
            return;
        }

        std::ostringstream oss;
        oss << "의심되는 블록 처리 감지 (길이 >= " << *it
            << ", RIP=0x" << std::hex << regs64->rip << ")";

        Detection detection;
        detection.rule_name = name();
        detection.description = oss.str();
        detection.address = snapshot.event.address;
        detection.timestamp = snapshot.timestamp;
        out.push_back(std::move(detection));
    }
};

class AesSBoxRule : public CryptoRule {
public:
    std::string name() const override { return "AesSBoxSignature"; }

    void Evaluate(const Snapshot& snapshot,
                  std::vector<Detection>& out) override {
        static constexpr std::array<std::uint8_t, 16> kAesPrefix = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76};

        if (ContainsPattern(snapshot.code_window, kAesPrefix) ||
            ContainsPattern(snapshot.stack_window, kAesPrefix)) {
            Detection detection;
            detection.rule_name = name();
            detection.description =
                "AES S-box 패턴과 일치하는 메모리 시퀀스를 발견했습니다.";
            detection.address = snapshot.event.address;
            detection.timestamp = snapshot.timestamp;
            out.push_back(std::move(detection));
        }
    }

private:
    template <typename Container, typename Pattern>
    static bool ContainsPattern(const Container& haystack,
                                const Pattern& needle) {
        if (haystack.size() < needle.size()) {
            return false;
        }
        return std::search(haystack.begin(), haystack.end(), needle.begin(),
                           needle.end()) != haystack.end();
    }
};

class ChaChaConstantRule : public CryptoRule {
public:
    std::string name() const override { return "ChaChaConstant"; }

    void Evaluate(const Snapshot& snapshot,
                  std::vector<Detection>& out) override {
        if (Contains(snapshot.code_window) || Contains(snapshot.stack_window)) {
            Detection detection;
            detection.rule_name = name();
            detection.description =
                "ChaCha20 시그마 상수 문자열이 감지되었습니다.";
            detection.address = snapshot.event.address;
            detection.timestamp = snapshot.timestamp;
            out.push_back(std::move(detection));
        }
    }

private:
    static bool Contains(const std::vector<std::uint8_t>& buffer) {
        if (buffer.size() < kChaChaSigma.size()) {
            return false;
        }
        return std::search(buffer.begin(), buffer.end(), kChaChaSigma.begin(),
                           kChaChaSigma.end()) != buffer.end();
    }
};

}  // namespace

Analyzer::Analyzer(AnalyzerConfig config) : config_(config) {
    RegisterRule(std::make_unique<BlockCopyHeuristicRule>());
    RegisterRule(std::make_unique<AesSBoxRule>());
    RegisterRule(std::make_unique<ChaChaConstantRule>());
}

void Analyzer::RegisterRule(std::unique_ptr<CryptoRule> rule) {
    if (!rule) {
        return;
    }
    rules_.push_back(std::move(rule));
}

std::vector<Detection> Analyzer::ProcessSnapshot(const Snapshot& snapshot) {
    std::vector<Detection> current;
    current.reserve(rules_.size());
    for (const auto& rule : rules_) {
        rule->Evaluate(snapshot, current);
    }
    detections_.insert(detections_.end(), current.begin(), current.end());
    return current;
}

}  // namespace dynscanner

