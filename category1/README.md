# Category 1: OpenMetadata Attack (2024)

**한국어** | [English](README_EN.md)

## 실제 사례

2024년 공격자들은 OpenMetadata의 원격 코드 실행 취약점을 악용해 Kubernetes에서 실행 중인 애플리케이션 Pod에 진입했습니다. 침해 후 시스템과 환경을 정찰하고, 환경변수와 자격증명 파일을 탐색한 뒤 추가 payload와 shell을 실행하는 흐름이 관찰됐습니다. 실제 공격 흐름은 [Microsoft Threat Intelligence의 2024 분석](https://www.microsoft.com/en-us/security/blog/2024/04/17/attackers-exploiting-new-critical-openmetadata-vulnerabilities-on-kubernetes-clusters/)에서 확인할 수 있습니다.

> 이 실습은 실제 악성코드나 외부 reverse shell을 재현하지 않습니다. Falco가 탐지할 수 있는 파일·프로세스 행위만 로컬에서 안전하게 단순화합니다.

## 공격 행위 대응

| 스크립트 | 실제 공격 단계 | 안전한 실습 행위 | Falco 구분값 |
| --- | --- | --- | --- |
| `normal.sh` | 정상 운영 기준선 | `sh`, `cat`, `curl`, 설정 읽기, `/tmp` 작업, health check | `scenario=normal` |
| `abnormal_1.sh` | reconnaissance 및 credential discovery | 환경변수, `/proc/1/environ`, 일반 credential 경로 탐색 | `scenario=abnormal_1` |
| `abnormal_2.sh` | Kubernetes credential access | 마운트된 ServiceAccount token 읽기 | `scenario=abnormal_2` |
| `abnormal_3.sh` | payload 및 shell 실행 | 네트워크 연결 없는 로컬 payload marker 실행 | `scenario=abnormal_3` |

## 실행 및 로그

터미널 1:

```bash
kubectl logs -n falco \
  -l app.kubernetes.io/name=falco \
  -c falco --prefix --follow | grep --line-buffered PBL_EVENT
```

터미널 2:

```bash
cd pbl-project
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh
```

최근 이벤트:

```bash
kubectl logs -n falco \
  -l app.kubernetes.io/name=falco \
  -c falco --prefix --since=10m | grep PBL_EVENT
```

정상은 예상된 설정·임시 파일 활동이고, 비정상은 discovery, token read, payload execution으로 `action` 값이 달라집니다. 예시는 `logs/normal.log`, `logs/abnormal_1.log`부터 `abnormal_3.log`까지 확인합니다.
