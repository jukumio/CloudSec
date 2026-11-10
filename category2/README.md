# Category 2: Hildegard / TeamTNT (2021)

**한국어** | [English](README_EN.md)

## 실제 사례

Unit 42가 2021년 공개한 Hildegard 캠페인에서 TeamTNT는 익명 접근이 가능한 kubelet을 통해 명령을 실행하고, 내부 네트워크에서 kubelet과 컨테이너를 탐색한 뒤 다른 workload로 이동했습니다. masscan을 이용한 내부 스캔과 kubelet API 기반 lateral movement가 핵심이었습니다. 자세한 내용은 [Unit 42 Hildegard 분석](https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/)을 참고합니다.

> 이 실습은 masscan, 악성코드, miner, C2를 실행하지 않습니다. Hubble에서 탐지 가능한 목적지 수·포트 수·요청 빈도만 안전하게 단순화합니다.

## 공격 행위 대응

| 스크립트 | 실제 공격 단계 | 안전한 실습 행위 | Hubble 관찰점 |
| --- | --- | --- | --- |
| `normal.sh` | 정상 서비스 통신 | frontend→backend, backend→db, DNS, health check, retry를 3회 반복 | 소수의 고정 목적지, 80/53 포트, `FORWARDED` |
| `abnormal_1.sh` | 평소 경로 밖 접근 | frontend에서 db Service 직접 접근 | 새로운 목적지, `DROPPED` |
| `abnormal_2.sh` | workload discovery | 여러 Service와 Pod IP를 짧은 시간에 연속 탐색 | 목적지 fan-out과 빈도 증가 |
| `abnormal_3.sh` | kubelet/서비스 probing | 여러 대상에 22, 443, 2379, 10250, 3306, 6379 연결 시도 | 목적지·포트 fan-out, 연속 `DROPPED` |

## 실행 및 로그

터미널 1:

```bash
cilium hubble port-forward
```

터미널 2:

```bash
hubble observe --namespace pbl-security --follow --output compact
```

터미널 3:

```bash
cd pbl-project
./category2/normal.sh
./category2/abnormal_1.sh
./category2/abnormal_2.sh
./category2/abnormal_3.sh
```

차단 흐름만 확인:

```bash
hubble observe --namespace pbl-security \
  --verdict DROPPED --since 10m --output compact
```

예시는 `logs/normal.log`, `logs/abnormal_1.log`부터 `abnormal_3.log`까지 확인합니다.
