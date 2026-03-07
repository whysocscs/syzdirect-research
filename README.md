# SyzDirect + LLM Agent Research

## 프로젝트 개요
SyzDirect (CCS 2023) 기반 directed greybox fuzzing + LLM Agent 보완 연구

**목표**: syscall 복잡도별 SyzDirect 실패 지점 측정 → LLM 에이전트로 R1/R2/R3 보완

## 케이스 할당
| Case | 담당 | 타겟 | 상태 |
|------|------|------|------|
| Case 2 | 호준 | drivers/block/nbd.c:2006 | 퍼징 완료 (dist=0) |
| Case 4 | 현영 | drivers/block/nbd.c:1809 | TPA 완료 |
| Case 6 | 상호 | drivers/misc/vmw_vmci/vmci_queuepair.c:542 | 퍼징 진행 중 |
| Case 8 | 나현 | drivers/net/bonding/bond_main.c:434 | 미셋업 |

## Case 6 파이프라인 완료 상태
- [x] srcs/case_6 (Linux 6.1 + kcov 패치)
- [x] bitcode/case_6 (vmci_queue_pair.llbc, nbd.llbc 교체)
- [x] interfaces (case_4 재활용)
- [x] tpa/case_6 → `qp_broker_alloc` / `ioctl$IOCTL_VMCI_QUEUEPAIR_ALLOC`
- [x] kwithdist/case_6 bzImage_nokvm (KCOV_INSTRUMENT_ALL=n)
- [ ] 퍼징 (KVM 환경 필요)

## 주요 파일
- `scripts/` : 빌드 및 실행 스크립트
- `scripts/fuzz_case6.sh` : Case 6 퍼징 원클릭 실행
- `scripts/watch_distance.sh` : 거리 감소 실시간 모니터링 + CSV 기록
- `configs/case_6/` : syz-manager 설정
- `results/tpa/case_6/` : TPA 결과 (distance 파일 포함)
- `source/kcov_patches/` : kcov_mark_block 삽입된 vmci 소스
- `source/syzdirect_patches/qemu.go` : SSH timeout 10분→30분 패치

## 중요 교훈
- `KCOV_INSTRUMENT_ALL=y` + `trace-pc,second` → TCG에서 int3 패닉 발생
- nokvm 환경에서는 반드시 `KCOV_INSTRUMENT_ALL=n` 사용
- SSH timeout을 30분으로 늘려야 TCG 부팅 대기 가능
- vmci TPA: dist 파일 3개 (vmci_host, vmci_queue_pair, v4l2-compat) = 정상
