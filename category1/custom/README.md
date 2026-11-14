# Category 1 사용자 구현: 탐지 규칙과 확장 평가

**한국어** | [English](README_EN.md)

이 폴더에는 기본 과제에 추가한 구현과 설명을 모았습니다. 제공된 규칙·시나리오는 상위 `category1/`에, 실행 원본과 당시 소스 사본은 저장소 루트의 `results/category1/`에 유지합니다.

| 파일 | 역할 |
| --- | --- |
| [falco-values-v2.yaml](falco-values-v2.yaml) | V2 탐지 규칙 |
| [apply-v2.sh](apply-v2.sh) | 기존 환경에 V2 배포 |
| [evaluate.sh](evaluate.sh) | 정상 7개·공격 모사 8개 평가 |
| [analyze_results.py](analyze_results.py) | 로그 분석 및 지표 집계 |
| [report.md](report.md) | 실제 결과와 오탐·미탐 분석 |

## 과제용 탐지 설계와 오탐·미탐 평가

[결과 보고서](report.md)에 탐지 근거, 실제 결과, 오탐·미탐, 한계를 정리합니다. 기본 시나리오의 탐지 성공을 확인한 뒤, 정상 업무와 변형 공격을 포함한 추가 평가로 규칙의 구분 능력을 확인합니다.

[기본 규칙](../falco-values.yaml)과 [V2 보완 규칙](falco-values-v2.yaml)을 같은 실행에 적용해 비교합니다. V2는 namespace와 컨테이너 역할을 제한하고, 읽기 프로그램 이름과 고정 payload 파일명에 대한 의존을 줄입니다. `env` 실행만으로는 공격이라고 단정하지 않고 정보 이벤트로 기록합니다. 승인된 유지보수 작업도 공격과 같은 파일·프로세스 행위를 만들 수 있으므로, 경고는 조사 대상이며 악성 의도의 증명이 아닙니다.

이 배포는 두 규칙 집합을 함께 켜는 비교 실험용입니다. 기본 규칙과 V2의 지표는 각각 분리해 계산하며, 전체 경고를 합친 지표로 해석하지 않습니다.

공통 설치가 완료된 프로젝트 루트에서 순서대로 실행합니다. [적용 스크립트](apply-v2.sh)는 현재 `kind-pbl-security` context를 확인하고, 설치된 Helm chart 버전을 그대로 지정해 사전 렌더링 후 `--atomic`으로 배포합니다. 기존 규칙은 유지하며 배포 전후 설정과 이전 revision으로 복구하는 명령을 보관합니다. 첫 명령이 성공한 뒤 평가를 실행합니다.

```bash
bash category1/custom/apply-v2.sh
bash category1/custom/evaluate.sh
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
