# B007 (qrtr_tun_write_iter) - SyzDirect Fuzzing Results

## 실행 정보
- 시작: 2026-03-03 02:09 KST
- 종료: 2026-03-03 22:11 KST (약 20시간)
- 타겟: `net/qrtr/tun.c:92` (`qrtr_tun_write_iter`)
- 커밋: `291009f656e8`

## 최종 통계
- 총 실행: 1,898,756 executions
- 커버리지: 64,426 unique edges
- 시그널: 118,523 / 155,445
- Unique crashes: 9개 (총 15회)

## 크래시 목록
| 크래시 | 횟수 | 타겟 관련 |
|--------|------|-----------|
| WARNING in __alloc_skb | 2 | ✅ qrtr_tun_write_iter 콜스택 포함 |
| BUG: NULL ptr deref in vhci_shutdown_connection | 3 | ❌ |
| WARNING in vkms_vblank_simulate | 3 | ❌ |
| no output from test machine | 2 | ❌ |
| BUG: NULL ptr deref in amp_read_loc_assoc_final_data | 1 | ❌ |
| BUG: paging request in imageblit | 1 | ❌ |
| unregister_netdevice: waiting for DEV | 1 | ❌ |
| INFO: task hung in hub_port_init | 1 | ❌ |
| possible deadlock in console_lock_spinning_enable | 1 | ❌ |

## 핵심 발견
WARNING in __alloc_skb 크래시의 콜스택:
```
qrtr_tun_write_iter+0xd3/0x130
qrtr_endpoint_post+0x58/0x640
__alloc_skb+0x1b8/0x270
```
→ 타겟 함수 도달 확인. 정확한 취약점 라인(tun.c:92) 도달 여부는 추가 분석 필요.

## 판정
- R1/R2/R3 분류: 추가 분석 필요
- 타겟 버그 재현: 불명확 (타겟 함수는 도달)
