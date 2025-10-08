# DynScanner DBG 설계 개요

본 문서는 어셈블리어 단위 디버깅을 활용한 동적 암호화 스캐너를 구현하기 위한 아키텍처 제안을 정리한다. Windows, Linux, ARM/AMD/x86 등 다양한 환경을 지원하는 것을 목표로 한다.

## 현재 구현 현황

* Linux 전용 `ptrace` 기반 디버그 세션 초깃값을 구현하였다.
  * `fork`/`execvp`로 타깃 프로세스를 실행하고, `PTRACE_TRACEME` + `SIGSTOP`으로 디버깅을 준비한다.
  * `waitpid` 이벤트를 `ProcessStart`/`ProcessExit`/`Signal`/`Breakpoint`로 변환하는 최소 이벤트 루프를 제공한다.
  * `PTRACE_CONT`를 통해 타깃 실행을 재개하고, `SIGKILL`로 세션 종료를 보장한다.
* 공통 `DebugSession` 팩토리(`DebugSession::Launch`)와 CLI 예제(`dynscanner_cli`)를 추가하였다.
  * `dynscanner_cli --target <실행파일> [-- 인자...]`로 타깃 프로그램을 실행하고 이벤트 로그를 확인할 수 있다.

### 빌드 방법 (Linux)

```bash
cmake -S . -B build
cmake --build build
./build/dynscanner_cli --target /bin/true
```

> 다른 플랫폼 구현체는 앞으로 순차적으로 추가될 예정이다.

## 1. 핵심 아이디어

* 대상 프로세스를 일시 중단 상태로 생성하거나 이미 실행 중인 프로세스에 디버거로 attach 한다.
* 분석하고자 하는 명령어 주소에 소프트웨어 브레이크포인트(예: x86의 `0xCC`, AArch64의 `BRK`)를 삽입한다.
* 브레이크포인트 예외가 발생할 때마다 레지스터, 메모리 상태를 수집하고 암호화 알고리즘 여부를 판단한다.
* 원본 명령어를 복원하고 프로그램 카운터를 조정한 뒤 실행을 이어간다.

## 2. 계층화된 구조

```
┌────────────────┐
│  Frontend CLI  │
└───────┬────────┘
        │ 명령/구성 전달
┌───────▼────────┐
│ Core Analyzer  │  ← 암호화 패턴 탐지, 규칙 엔진
└───────┬────────┘
        │ Breakpoint 이벤트
┌───────▼────────┐
│ Debug Session  │  ← 공통 인터페이스(IDebugSession)
└───────┬────────┘
   ┌────▼────┐┌───▼────┐
   │WinDBG   ││Ptrace  │ … 플랫폼 어댑터
   └─────────┘└────────┘
```

### 2.1 IDebugSession (공통 인터페이스)

* `launch(target, args, options)` / `attach(pid)`
* `set_breakpoint(address)` / `remove_breakpoint(address)`
* `read_memory(addr, size)` / `write_memory(addr, data)`
* `get_registers(thread)` / `set_registers(thread, regs)`
* `resume(thread=None)` / `single_step(thread)`
* 이벤트 스트림: `BreakpointHit`, `SingleStep`, `Exception`, `ProcessExit`

### 2.2 플랫폼별 어댑터

| 플랫폼 | 구현 포인트 |
| ------ | ------------ |
| Windows (x86/x64/ARM64) | `CreateProcess(DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED)`, `WaitForDebugEvent`, `ContinueDebugEvent`, `Read/WriteProcessMemory`, `Get/SetThreadContext` 활용 |
| Linux (x86/x64/ARM/AArch64) | `ptrace(PTRACE_TRACEME/ATTACH/CONT/STEP/GETREGS/SETREGS/POKETEXT)`, `waitpid`, `siginfo_t` 이벤트 처리 |
| macOS/BSD | Mach 예외 포트 또는 `ptrace` 유사 API 사용, 코드서명 우회 대비 |

각 어댑터는 공통 인터페이스를 구현하고, 브레이크포인트 명령어 길이 및 PC 조정 로직을 캡슐화한다.

## 3. 브레이크포인트 관리

1. 브레이크포인트 등록 시 원본 명령어 바이트를 저장한다.
2. 아키텍처별 트랩 명령어 길이를 고려하여 PC 보정 로직을 제공한다.
3. 예외 처리 시:
   1. 원본 명령어 복원
   2. PC 보정 (예: x86 → `RIP -= 1`, AArch64 → `PC -= 4`)
   3. 단일 스텝 또는 재설치 로직 실행
4. 재개 전에 필요 시 단일 스텝으로 원본 명령어 실행 후 브레이크포인트를 재설치한다.

## 4. 레지스터/메모리 스냅샷

* 공통 구조체를 정의해 아키텍처별 레지스터를 맵핑한다 (예: `RegStateX64`, `RegStateAArch64`).
* 스냅샷은 분석 파이프라인으로 전달되어 암호화 루틴 탐지에 활용된다.
* 엔디언 변환 및 정렬을 고려한 메모리 읽기 헬퍼를 제공한다.

## 5. 암호화 탐지 파이프라인

1. **이벤트 수집층**: 각 브레이크포인트 히트마다 레지스터/메모리/스택 정보를 기록.
2. **휴리스틱 탐지**: 반복 루프, 대량 메모리 복사, 특정 상수(S-box, 라운드 키 길이) 등을 활용.
3. **패턴 시그니처**: 알고리즘별 명령어 시퀀스 템플릿(AES, ChaCha20 등) 정의.
4. **동적 분석**: 짧은 구간을 에뮬레이션하여 키 스케줄/라운드 동작을 검증.
5. **리포팅**: JSON/프로토콜 버퍼 기반 아티팩트로 기록.

규칙 엔진은 스크립트(Python/Lua)로 확장 가능하도록 설계하여 새로운 알고리즘 지원을 손쉽게 추가한다.

## 6. 빌드 & 테스트 전략

* CMake 기반 다중 플랫폼 빌드 스크립트.
* Windows: MSVC / clang-cl, Linux: GCC/Clang, macOS: Xcode toolchain.
* CI에서 QEMU를 활용한 크로스 아키텍처 단위 테스트 및 샘플 암호화 프로그램 실행.
* 테스트 타깃: 간단한 XOR, AES, ChaCha20 구현을 포함한 멀티 아키텍처 바이너리.

## 7. 보안 및 안정성 고려 사항

* 디버거 종료 시 원본 코드와 상태를 반드시 복원.
* 안티디버깅 대응: 타이밍 보정, `IsDebuggerPresent` 후킹, `ptrace` 자기 검사 방어.
* 권한 관리: Windows 관리자 권한/UAC, Linux Capabilities 설정.
* 로그 보존 및 법적 가이드라인 문서화.

## 8. 향후 확장 아이디어

* 하드웨어 브레이크포인트/PMU를 활용한 고성능 추적.
* 동적 코드 변조(Just-In-Time 패치)에 대응하기 위한 실시간 바이너리 재분석.
* GUI 기반 시각화 도구(타임라인, 메모리 맵, 키 추적 그래프).

---

해당 설계는 기본적인 구조를 제시하는 것으로, 실제 구현에서는 각 플랫폼의 세부 API 제약과 성능, 보안 요구사항을 추가로 검토해야 한다.
