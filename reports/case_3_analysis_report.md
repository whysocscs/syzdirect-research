# Case_3 분석 보고서: net/sched/sch_taprio.c:919

## 1. 타겟 개요

| 항목 | 값 |
|------|-----|
| Case | case_3 |
| 타겟 파일 | net/sched/sch_taprio.c |
| 타겟 라인 | 919 |
| 타겟 함수 | `parse_taprio_schedule()` (caller: `taprio_change`) |
| 커널 버전 | 6.1.0 |
| 서브시스템 | net/sched (TC - taprio qdisc) |

## 2. 타겟 코드 분석

`parse_taprio_schedule()`은 taprio qdisc의 스케줄 설정 파싱:

```c
static int parse_taprio_schedule(struct taprio_sched *q, struct nlattr **tb,
                                  struct sched_gate_list *new,
                                  struct netlink_ext_ack *extack)
{
    // parse base_time, cycle_time_extension, cycle_time
    // parse entry list
    // validate cycle_time
    kcov_mark_block(0);  // ← TARGET (line 919)
    return 0;
}
```

실제 호출 체인:
```
sendmsg(netlink, RTM_NEWQDISC)
  → rtnetlink_rcv_msg()
    → tc_modify_qdisc()
      → qdisc_change() / taprio_change()
        → parse_taprio_schedule()
          → [line 919: TARGET]
```

## 3. 파이프라인 실행 결과

### Step 2: CompileKernelToBitcode
- **6,817개 .llbc** (비어있지 않은 것: 6,737개)
- 디스크 부족으로 vmlinux 링크 실패 (bitcode는 정상)

### Step 3: AnalyzeKernelInterface
- 34개 청크, 5개 실패 (chunk_016, 020, 022, 026, 031)
- **kernel_signature_full**: 11,328개 시그니처
- **kernelCode2syscall.json**: 1,023개 핸들러 매핑

### Step 4: AnalyzeTargetPoints (TPA)
- drivers/ 제외 4,009 파일 subset
- 성공 (457초)
- **distance_xidx0/**: 3,672개 distance 파일
- **CompactOutput.json**: 16개 target syscall 매핑

## 4. R1 분석 결과: **NOISY SUCCESS**

### 발견된 Target Syscall (16개)

| Syscall | Constraints | 평가 |
|---------|------------|------|
| `bind$xdp` | 없음 | false positive |
| `getsockopt$inet_buf` | 없음 | false positive |
| `ioctl$sock_bt_bnep_BNEPCONNADD` | string:"taprio" | false positive |
| `ioctl$sock_inet_SIOCADDRT` | 없음 | false positive |
| `ioctl$sock_inet_SIOCDARP` | string:"taprio" | false positive |
| `ioctl$sock_inet_SIOCDELRT` | 없음 | false positive |
| `ioctl$sock_inet_SIOCGARP` | string:"taprio" | false positive |
| `ioctl$sock_inet_SIOCSIFADDR` | string:"taprio" | **간접 관련** |
| `ioctl$sock_inet_SIOCSIFNETMASK` | string:"taprio" | **간접 관련** |
| `setsockopt` | SO_BINDTODEVICE, "taprio" | **간접 관련** |
| `setsockopt$inet6_IPV6_XFRM_POLICY` | string:"taprio" | false positive |
| `setsockopt$inet6_buf` | string:"taprio" | false positive |
| `setsockopt$inet6_int` | string:"taprio" | false positive |
| `setsockopt$inet_int` | 없음 | false positive |
| `setsockopt$inet_mtu` | 없음 | false positive |
| `write` | 없음 | false positive |

### 핵심 문제

**Precision: ~0%** — 16개 매핑 중 직접 도달 가능한 것이 **없음**.

실제 도달 경로는 `sendmsg` → rtnetlink → `tc_modify_qdisc` → `taprio_change`이지만:
- `rtnl_register(RTM_NEWQDISC, tc_modify_qdisc, ...)` 패턴을 interface_generator가 인식하지 못함
- 대신 "taprio"라는 문자열 매칭으로 관련 없는 syscall들이 연결됨
- case_0과 **동일한 rtnl_register 패턴 미인식 문제**

## 5. Case_0 vs Case_3 비교 (같은 net/sched 서브시스템)

| 항목 | Case_0 (cls_tcindex) | Case_3 (sch_taprio) |
|------|---------------------|---------------------|
| 타겟 함수 | tcindex_alloc_perfect_hash | parse_taprio_schedule |
| R1 결과 | FAIL (0개 매핑) | NOISY SUCCESS (16개, 유효 0개) |
| 인터페이스 | rtnl_register | rtnl_register |
| 실질 효과 | 동일 — 올바른 syscall 미발견 |

## 6. 전체 Case 비교

| Case | 서브시스템 | 인터페이스 | R1 | 유효 매핑 |
|------|-----------|-----------|-----|----------|
| 0 | net/sched (TC) | rtnl_register | FAIL | 0/0 |
| 1 | sound/seq (ALSA) | ioctl | SUCCESS | 3/6 |
| 2 | drivers/block (NBD) | genetlink | SUCCESS | 1/1 |
| 3 | net/sched (TC) | rtnl_register | NOISY | 0/16 |

**패턴**: rtnl_register 기반 서브시스템은 SyzDirect가 일관되게 실패.

## 7. 다음 단계

- [x] R1 분석 완료 (NOISY SUCCESS - 실질적 FAIL)
- [ ] Case_4 (drivers/block/nbd.c:1809) 분석 진행
