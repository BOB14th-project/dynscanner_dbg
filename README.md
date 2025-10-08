# DynScanner DBG 설계 개요

본 문서는 어셈블리어 단위 디버깅을 활용한 동적 암호화 스캐너를 구현하기 위한 아키텍처 제안과 현재 구현 현황을 정리한다. Windows, Linux, ARM/AMD/x86 등 다양한 환경을 지원하는 것을 목표로 한다.

## 현재 구현 현황

* 공통 `DebugSession` 인터페이스를 `Launch`/`Attach`/`resume`/`single_step`/`get_thread_registers` 등 아키텍처 중립 API로 확장하였다.
  * 레지스터 표현(`RegisterState`)은 x86/x86-64/ARM/AArch64 구조체를 포함하도록 설계되었으며 현재는 Linux x86-64에서 완전 동작한다.
  * 소프트웨어 브레이크포인트는 원본 코드 바이트를 보존·복원하며 단일 스텝 후 재설치하는 루프를 제공한다.
  * 원격 메모리 I/O(`read_memory`/`write_memory`)가 단위 바이트 단위로 구현되어 코드/스택 스냅샷 확보가 가능하다.

* Linux `ptrace` 백엔드는 다음 기능을 지원한다.
  * `PTRACE_TRACEME`/`fork`/`execve`를 통한 프로세스 실행, 혹은 `PTRACE_ATTACH` 기반 기존 프로세스 부착.
  * `waitpid(-1, __WALL)` 이벤트를 `ProcessStart`/`Breakpoint`/`SingleStep`/`Signal`/`ProcessExit`로 변환한다.
  * 단일 스텝 중인지 추적하여 `SIGTRAP`을 `Breakpoint`와 `SingleStep`으로 구분한다.
  * 디버거 종료 시 모든 브레이크포인트를 원본 코드로 복원 후 `SIGKILL` 또는 `PTRACE_DETACH`로 정리한다.

* Windows Win32 디버깅 백엔드가 추가되어 `CreateProcess(DEBUG_ONLY_THIS_PROCESS)`와 `WaitForDebugEvent` 루프, `Get/SetThreadContext`,
  `Read/WriteProcessMemory`를 사용해 x86/x64/ARM64 소프트웨어 브레이크포인트 흐름을 제어한다.
  * 0xCC/BRK/BKPT 패턴을 자동으로 선택하고, 스레드 핸들을 캐시하여 `ResumeThread`/`ContinueDebugEvent` 호출 전 PC 복원·단일 스텝을 지원한다.
  * `IsWow64Process2` 기반으로 타깃 아키텍처를 판별하여 32비트 프로세스와 WoW64, ARM64 원격 레지스터 구조체로 매핑한다.
* macOS Mach 예외 포트 백엔드는 `task_set_exception_ports`와 `mach_exc_server`를 통해 브레이크포인트·싱글스텝 예외를 수신한다.
  * `mach_vm_read_overwrite`/`mach_vm_write`로 메모리 스냅샷을 확보하고, `thread_get_state`/`thread_set_state`를 이용해 x86/x86_64/AArch64 레지스터를 변환한다.
  * 예외 응답은 지연된 `mach_msg` reply를 통해 재개되며, x86 계열은 Trap Flag 기반 단일 스텝, ARM64는 `PT_STEP` 보조 호출을 사용한다.
* `dynscanner_cli`는 계층화된 분석 파이프라인을 제공한다.
  * `--target` 또는 `--attach`로 대상 프로세스를 제어하고, 다수의 `--breakpoint`를 설정할 수 있다.
  * 브레이크포인트 히트 시 코드/스택 스냅샷을 채취하고 `Analyzer`에 전달한다.
  * 내장 규칙은 AES S-box, ChaCha20 시그마 상수, 대량 블록 처리 휴리스틱을 감지하며 결과를 실시간 로그로 출력한다.
  * 옵션으로 코드/스택 스냅샷 크기 조정, 환경 변수 설정, 작업 디렉터리 지정이 가능하다.

### 빌드 방법 (Linux)

```bash
cmake -S . -B build
cmake --build build
./build/dynscanner_cli --target /bin/true
```

### 사용 예시

```bash
# 대상 실행 파일과 브레이크포인트 설정
./build/dynscanner_cli \
  --target ./samples/crypto_target \
  --breakpoint 0x401000 --breakpoint 0x401050 \
  --code-window 128 --stack-window 256

# 실행 중인 PID에 부착
./build/dynscanner_cli --attach 12345 --breakpoint 0x401000
```

> 현재는 Linux(x86/x86_64), Windows(x86/x64/ARM64), macOS(x86_64/ARM64) 백엔드가 구현되어 있으며, ARM/Thumb 등 세부 튜닝과 고급 예외 처리 로직은 지속적으로 확장될 예정이다.

## 1. 핵심 아이디어

* 대상 프로세스를 일시 중단 상태로 생성하거나 이미 실행 중인 프로세스에 디버거로 attach 한다. *(구현 완료)*
* 분석하고자 하는 명령어 주소에 소프트웨어 브레이크포인트(예: x86의 `0xCC`, AArch64의 `BRK`)를 삽입한다. *(x86-64 구현 완료)*
* 브레이크포인트 예외가 발생할 때마다 레지스터, 메모리 상태를 수집하고 암호화 알고리즘 여부를 판단한다. *(Analyzer 스냅샷 파이프라인 구현)*
* 원본 명령어를 복원하고 프로그램 카운터를 조정한 뒤 실행을 이어간다. *(단일 스텝 기반 복원 루프 구현)*

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

* `launch(target, args, options)` / `attach(pid)` *(구현됨)*
* `set_breakpoint(address)` / `remove_breakpoint(address)` *(구현됨 — x86-64)*
* `read_memory(addr, size)` / `write_memory(addr, data)` *(구현됨)*
* `get_registers(thread)` / `set_registers(thread, regs)` *(구현됨 — x86/x86-64)*
* `resume(thread=None)` / `single_step(thread)` *(구현됨)*
* 이벤트 스트림: `BreakpointHit`, `SingleStep`, `Exception`, `ProcessExit` *(현재 `Signal`/`Breakpoint`/`SingleStep`/`ProcessStart`/`ProcessExit` 구현)*

### 2.2 플랫폼별 어댑터

| 플랫폼 | 구현 포인트 |
| ------ | ------------ |
| Windows (x86/x64/ARM64) | `CreateProcess(DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED)`, `WaitForDebugEvent`, `ContinueDebugEvent`, `Read/WriteProcessMemory`, `Get/SetThreadContext` 활용 |
| Linux (x86/x64/ARM/AArch64) | `ptrace(PTRACE_TRACEME/ATTACH/CONT/STEP/GETREGS/SETREGS/POKETEXT)`, `waitpid`, `siginfo_t` 이벤트 처리 *(x86/x86-64 구현 완료, ARM/AArch64 준비됨)* |
| macOS/BSD | Mach 예외 포트 또는 `ptrace` 유사 API 사용, 코드서명 우회 대비 |

각 어댑터는 공통 인터페이스를 구현하고, 브레이크포인트 명령어 길이 및 PC 조정 로직을 캡슐화한다.

## 3. 브레이크포인트 관리

1. 브레이크포인트 등록 시 원본 명령어 바이트를 저장한다. *(구현됨 — `BreakpointInfo`)*
2. 아키텍처별 트랩 명령어 길이를 고려하여 PC 보정 로직을 제공한다. *(x86-64 구현 완료, 타 아키텍처 확장 예정)*
3. 예외 처리 시:
   1. 원본 명령어 복원 *(구현됨)*
   2. PC 보정 (예: x86 → `RIP -= 1`, AArch64 → `PC -= 4`) *(x86-64 구현 완료)*
   3. 단일 스텝 또는 재설치 로직 실행 *(구현됨)*
4. 재개 전에 필요 시 단일 스텝으로 원본 명령어 실행 후 브레이크포인트를 재설치한다. *(구현됨 — CLI 루프에서 수행)*

## 4. 레지스터/메모리 스냅샷

* 공통 구조체를 정의해 아키텍처별 레지스터를 맵핑한다 (예: `RegStateX64`, `RegStateAArch64`). *(구현됨 — `RegisterState`)*
* 스냅샷은 분석 파이프라인으로 전달되어 암호화 루틴 탐지에 활용된다. *(구현됨 — `Analyzer::ProcessSnapshot`)*
* 엔디언 변환 및 정렬을 고려한 메모리 읽기 헬퍼를 제공한다. *(구현됨 — 워드 단위 읽기/쓰기)*

## 5. 암호화 탐지 파이프라인

1. **이벤트 수집층**: 각 브레이크포인트 히트마다 레지스터/메모리/스택 정보를 기록. *(CLI + Analyzer에서 구현)*
2. **휴리스틱 탐지**: 반복 루프, 대량 메모리 복사, 특정 상수(S-box, 라운드 키 길이) 등을 활용. *(BlockCopy/AES/ChaCha 규칙 구현)*
3. **패턴 시그니처**: 알고리즘별 명령어 시퀀스 템플릿(AES, ChaCha20 등) 정의. *(초기 시그니처 구현 완료)*
4. **동적 분석**: 짧은 구간을 에뮬레이션하여 키 스케줄/라운드 동작을 검증. *(후속 작업 — 인터페이스 준비됨)*
5. **리포팅**: JSON/프로토콜 버퍼 기반 아티팩트로 기록. *(향후 구현 예정, 현재 콘솔 로그 제공)*

규칙 엔진은 C++ 클래스 기반으로 확장 가능하며, 향후 스크립트 기반 플러그인 추가 여지를 남겨두었다.

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
### 빌드 방법 (Windows)

Windows용 바이너리는 Win32 디버깅 API와 `dbghelp` 라이브러리에 의존하므로, 관리자 권한 PowerShell 또는 개발자 명령 프롬프트에서 다음 명령을 실행한다.

```powershell
cmake -S . -B build -G "Ninja" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
./build/dynscanner_cli.exe --target C:\\Windows\\System32\\notepad.exe --breakpoint 0x401000
```

> Visual Studio Generator를 사용하는 경우 `-G "Visual Studio 17 2022"` 옵션으로 구성 후 `cmake --build build --config RelWithDebInfo`를 실행한다.

### 빌드 방법 (macOS)

macOS에서는 Mach 예외 포트를 사용하므로, 코드 서명 및 권한 요구 사항을 충족한 상태에서 아래 명령으로 빌드한다.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
./build/dynscanner_cli --target /usr/bin/true
```

> macOS에서 `task_for_pid` 접근을 위해서는 루트 권한 또는 `com.apple.security.cs.debugger` 서명이 필요하다.
