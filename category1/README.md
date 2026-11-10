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
  -c falco --prefix --follow --tail=0 \
  | grep --line-buffered -E 'PBL(_V2)?_EVENT'
```

터미널 2:

```bash
cd Practical-Cloud-Security-PBL
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh
```

최근 이벤트:

```bash
kubectl logs -n falco \
  -l app.kubernetes.io/name=falco \
  -c falco --prefix --since=10m --tail=-1 \
  | grep -E 'PBL(_V2)?_EVENT'
```

정상은 예상된 설정·임시 파일 활동이고, 비정상은 discovery, token read, payload execution으로 `action` 값이 달라집니다. 예시는 `logs/normal.log`, `logs/abnormal_1.log`부터 `abnormal_3.log`까지 확인합니다.

## 과제용 탐지 설계와 오탐·미탐 평가

[결과 보고서](../results/category1/report.md)에 탐지 근거, 실제 결과, 오탐·미탐, 한계를 정리합니다. 기본 시나리오의 탐지 성공을 확인한 뒤, 정상 업무와 변형 공격을 포함한 추가 평가로 규칙의 구분 능력을 확인합니다.

[기본 규칙](falco-values.yaml)과 [V2 보완 규칙](falco-values-v2.yaml)을 같은 실행에 적용해 비교합니다. V2는 namespace와 컨테이너 역할을 제한하고, 읽기 프로그램 이름과 고정 payload 파일명에 대한 의존을 줄입니다. `env` 실행만으로는 공격이라고 단정하지 않고 정보 이벤트로 기록합니다. 승인된 유지보수 작업도 공격과 같은 파일·프로세스 행위를 만들 수 있으므로, 경고는 조사 대상이며 악성 의도의 증명이 아닙니다.

이 배포는 두 규칙 집합을 함께 켜는 비교 실험용입니다. 기본 규칙과 V2의 지표는 각각 분리해 계산하며, 전체 경고를 합친 지표로 해석하지 않습니다.

공통 설치가 완료된 프로젝트 루트에서 순서대로 실행합니다. [적용 스크립트](apply-v2.sh)는 현재 `kind-pbl-security` context를 확인하고, 설치된 Helm chart 버전을 그대로 지정해 사전 렌더링 후 `--atomic`으로 배포합니다. 기존 규칙은 유지하며 배포 전후 설정과 이전 revision으로 복구하는 명령을 보관합니다. 첫 명령이 성공한 뒤 평가를 실행합니다.

```bash
bash category1/apply-v2.sh
bash category1/evaluate.sh
```

[평가 스크립트](evaluate.sh)는 정상 7개와 공격 모사 8개, 총 15개의 통제된 사례를 실행합니다. 정상 환경변수 조회, 실행하지 않은 경로 문자열, 승인된 임시 스크립트와 token 접근을 포함하고, 공격 모사에는 `head`를 이용한 읽기, payload 이름 변경, shell sourcing 등을 포함합니다. token과 환경정보의 내용은 출력하지 않습니다. 정상·공격 정답은 실험에서 정한 실행 목적이며, 해당 목적을 Falco가 독립적으로 알아내는 것은 아닙니다.

배포 근거는 `results/category1/deployment-<UTC>-<pid>/`, 평가 근거는 `results/category1/evaluation-<UTC>-<pid>/`에 새 폴더로 저장됩니다. [분석기](analyze_results.py)는 평가 후 자동으로 실행됩니다.

| 평가 파일 | 내용 |
| --- | --- |
| `cases.jsonl`, `commands/` | 실행 목적, 명령의 성공 여부, 시간 구간, 대상 컨테이너, stdout·stderr |
| `logs/`, `active-helm-values.json` | Falco 원본 로그 전체와 평가에 적용된 규칙 설정 |
| `cases.csv` | 사례별 기본 규칙·V2의 예상값과 실제 TP·TN·FP·FN |
| `summary.md`, `summary.json`, `events.jsonl` | 수집 상태, 사례별 근거, 지표와 파싱한 이벤트 |

완료된 사례 1개를 표본 1개로 세며, 여러 센서나 부모·자식 프로세스가 만든 중복 경고를 공격 횟수로 세지 않습니다. 평가는 기본 PBL 규칙과 V2 규칙의 `Warning` 이상만 비교합니다. Falco 기본 규칙과 기타 경고도 원본에 보관하고 따로 표시하므로, PBL 규칙의 미탐을 Falco 전체의 미탐으로 해석하지 않습니다.

명령 실패, 센서 재시작, 수집 실패 등은 평가에서 제외하거나 확인되지 않은 결과로 표시합니다. 경고가 없는 사례는 유한한 수집 구간에서 관찰된 비탐지입니다. 이벤트 손실 지표는 측정하지 않았으므로 손실이 없었다고 가정할 수 없고, 소규모 사례의 지표를 운영 환경의 정확도로 일반화하지 않습니다. 자세한 판단 근거와 남은 오탐·미탐은 보고서에서 확인합니다.
