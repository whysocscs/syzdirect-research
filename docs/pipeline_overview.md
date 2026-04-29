# CVE 기반 자동 타겟 퍼징 파이프라인

> SyzDirect + LLM을 결합한 취약점 자동 재현 시스템 흐름도

---

## 전체 흐름 (Mermaid)

```mermaid
flowchart TD
    INPUT["📥 INPUT\nCVE-XXXX-XXXXX"]

    subgraph S1["① CVEResolver — 패치 커밋 자동 탐색 🟢"]
        A1["kernel-vulns repo → NVD API → GitHub 커밋 검색"]
        A2["패치 diff 파싱\n수정 파일 · 함수명 · vulnerable commit(fix~1) 추출"]
        A1 --> A2
    end

    subgraph S2["② LLM Analyze — 패치 코드 기반 프롬프트 생성 🟡 LLM"]
        B1["패치 diff + 타겟 함수 소스 → LLM 프롬프트 구성"]
        B2["출력: 진입 시스콜 후보\n+ 관련 시스콜 체인\n+ 인자 제약 조건"]
        B1 --> B2
    end

    subgraph S3["③ 시스콜 검증 — LLM 결과 정제 🟣 VERIFY"]
        C1["syscall_normalize\nsyzkaller 콜 테이블 대조·이름 정규화"]
        C2["syscall_scoring\n실현 가능성·커버리지 기반 점수 계산"]
        C3["narrow_callfile\n상위 N개만 callfile 기록"]
        C1 --> C2 --> C3
    end

    subgraph S4["④ 커널 빌드 & 정적 분석 🔴"]
        D1["vulnerable commit 체크아웃 → kcov 패치 → 계측 빌드"]
        D2["InterfaceGenerator\n함수→시스콜 매핑, .dist 거리 파일 생성"]
        D1 --> D2
    end

    subgraph S5["⑤ SyzDirect 퍼징 루프 🔵 LLM 동적 강화"]
        E1["거리 기반 Directed Fuzzing 실행\n+ Health Monitor 모니터링"]
        E2{"실패 분류"}
        E3["R4: 거리 정체\n→ LLM으로 callfile 재강화"]
        E4["R3: 컨텍스트 부족\n→ RelatedSyscallAgent 실행"]
        E5["R2: 인자 생성 실패\n→ ObjectSynthesisAgent 실행"]
        E1 --> E2
        E2 -->|거리 정체| E3
        E2 -->|컨텍스트 부족| E4
        E2 -->|인자 생성 실패| E5
        E3 & E4 & E5 --> E1
    end

    OUTPUT["🏁 OUTPUT\n크래시 리포트 + .syz 재현 프로그램"]

    INPUT --> S1 --> S2 --> S3 --> S4 --> S5 --> OUTPUT
```

---

## 단계별 설명

| 단계 | 이름 | 핵심 동작 | 주요 모듈 |
|------|------|-----------|-----------|
| ① | **CVEResolver** | CVE ID → 패치 커밋 해시 자동 탐색 (3개 소스 순차 시도) | `cve_resolver.py` |
| ② | **LLM Analyze** | 패치 diff + 타겟 소스 기반 LLM 프롬프트 생성 및 호출 | `llm_enhance.py` |
| ③ | **시스콜 검증** | LLM 제안 시스콜의 유효성 검증 및 점수 기반 정제 | `syscall_normalize.py`, `syscall_scoring.py` |
| ④ | **커널 빌드** | kcov 계측 커널 빌드 + 함수→거리 정적 분석 | `kernel_build.py`, `InterfaceGenerate.py` |
| ⑤ | **퍼징 루프** | 거리 기반 퍼징 + 실패 분류 → 에이전트 피드백 강화 | `agent_loop.py`, `failure_triage.py` |

---

## LLM 활용 포인트

```
CVE 입력
   │
   ├─ [LLM #1] 패치 diff 분석
   │           패치로 수정된 코드를 읽고
   │           어떤 시스콜 체인이 취약 경로에 도달할 수 있는지 제안
   │
   └─ [LLM #2] 퍼징 중 동적 강화
               거리가 정체될 때 현재 callfile을 LLM에 재분석 요청
               → 새로운 시스콜 변형 / 인자 조합 추가
```

---

## 핵심 특징 요약

- **완전 자동화**: CVE 번호 하나로 패치 커밋 탐색 → 커널 빌드 → 퍼징까지 전 과정 자동 실행
- **LLM 이중 활용**: 초기 시스콜 체인 생성 + 퍼징 중 동적 재강화 두 단계에서 LLM 사용
- **검증 루프**: LLM 출력은 항상 syzkaller 콜 테이블·점수 계산을 거쳐 유효성 검증 후 사용
- **에이전트 피드백**: 실패 원인(R2/R3/R4)을 자동 분류해 전용 에이전트로 템플릿 강화
