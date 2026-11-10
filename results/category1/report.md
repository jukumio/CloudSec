# Category 1 결과 보고서: Pod 내부 행위 탐지와 정상·공격 구분

## 1. 결론과 평가 범위

정상 7개·공격 모사 8개의 통제 사례를 실제 실행하여 기존 규칙과 개선 규칙 V2를 비교했다. 사례 단위 관측 결과는 **기준선 TP 4 / TN 4 / FP 3 / FN 4**, **V2 TP 6 / TN 5 / FP 2 / FN 2**였다. 대체 읽기 도구와 변경된 payload 경로를 다루는 범위가 늘었으나, 정상 임시 스크립트의 경고와 `env` 단독 공격 탐색의 미탐이라는 절충점도 확인했다. [실제 실행 요약](evaluation-20261110T094358Z-114177/summary.md), [기계 판독 결과](evaluation-20261110T094358Z-114177/summary.json)

별도의 초기 수집 파일 [falco-events.log](falco-events.log)에는 제공된 정상 스크립트 1개와 공격 모사 스크립트 3개에 대응하는 이벤트 13건이 있다. 이 초기 자료와 확장 평가 15개 사례는 합산하지 않는다. 초기 자료는 기본 동작 검증에, 확장 평가는 규칙의 오탐·미탐과 개선 효과 비교에 사용했다.

정상·비정상 정답은 통제 사례 작성자가 선언한 행위 의도이고, Falco가 악성 여부를 독립적으로 판정한 결과는 아니다. 15개 사례는 개발 중 구성한 소규모 평가 집합이며, 운영 환경의 탐지 정확도나 일반적인 오탐률을 입증하지 않는다.

담당 범위는 Category 1의 Pod 내부 파일 접근과 프로세스 실행이다. Category 2의 네트워크 관찰과 Category 3의 Kubernetes API 감사 로그는 이 보고서의 측정 대상에서 제외했다. 워크로드는 [frontend](../../workload/frontend.yaml)와 [backend](../../workload/backend.yaml)의 BusyBox 기반 데모 애플리케이션이다. 실제 OpenMetadata 취약점 공격, 악성코드, 자격증명 유출, 외부 reverse shell 연결을 실행한 결과가 아니다.

## 2. 탐지 시스템과 규칙 설계

관찰 흐름은 다음과 같다.

```text
정상·공격 모사 스크립트
  → kubectl exec로 데모 컨테이너 내부 행위 발생
  → Falco가 커널 syscall / 프로세스 실행 이벤트 관찰
  → 커스텀 조건과 일치하는 이벤트에 규칙명·우선순위·action 부여
  → Falco JSON 로그 수집
  → 실행 시나리오, 실제 명령, 파일 경로, Pod 정보와 대조
```

[설치 스크립트](../../install.sh)는 Falco를 배포하고 JSON 출력, `rule_matching=all`, [커스텀 규칙 파일](../../category1/falco-values.yaml)을 설정한다. `rule_matching=all`에서는 기본 규칙과 커스텀 규칙이 함께 결과를 낼 수 있다. 초기 `falco-events.log`는 `PBL_EVENT`에 해당하는 실습 규칙 출력이다. 확장 평가는 전체 Falco 원본 로그를 보존하고 기준선·V2·기타 규칙을 나누어 분석했다.

| 시나리오 | 규칙이 실제로 확인하는 조건 | 출력 action | 우선순위 |
| --- | --- | --- | --- |
| 정상 설정 읽기 | `frontend`의 `cat`이 `/etc/hostname` 또는 `/www/index.html`을 `open/openat/openat2`로 접근 | `config_read` | Informational |
| 정상 임시 파일 작업 | `frontend`가 `/tmp/openmetadata-normal`로 시작하는 파일을 쓰기 모드로 열기 | `temp_file_write` | Informational |
| 정상 health check | 컨테이너가 `/tmp/openmetadata-health-response`를 쓰기 모드로 열기 | `health_check` | Informational |
| 공격 모사 1 | `backend`에서 `env` 실행 또는 인자에 `/proc/1/environ`을 포함한 `cat` 실행 | `credential_environment_discovery` | Warning |
| 공격 모사 2 | `backend`의 `cat`이 경로에 `kubernetes.io/serviceaccount`를 포함하고 `token`으로 끝나는 파일을 열기 | `serviceaccount_token_read` | Warning |
| 공격 모사 3 | `frontend`에서 `/tmp/openmetadata-payload.sh`가 인자에 포함된 `sh` 실행 | `payload_shell_exec` | Warning |

정상 시나리오도 shell과 `cat`을 사용한다. 따라서 단순히 “shell 실행”이나 “cat 사용”만으로 공격이라고 분류하지 않고, 컨테이너 역할, 접근 대상, 명령 인자를 결합한다. 다만 현재 조건은 실습에서 정한 컨테이너 이름과 경로에 맞춰져 있으며, 일반적인 공격 전체를 포괄하지 않는다. Falco의 조건·출력·우선순위 구분은 [공식 규칙 설명](https://falco.org/docs/concepts/rules/basic-elements/)을 참고했다.

## 3. 초기 13개 이벤트: 수집 결과와 판단 근거

측정 원본은 이 폴더의 [falco-events.log](falco-events.log)이다. 로그 시각은 `2026-11-10T09:24:00.020436134Z`부터 `09:24:05.622503443Z`까지이며, 한국 시각으로 2026-11-10 18:24:00~18:24:05이다. 접두사의 Falco Pod 이름은 **로그를 생성한 센서**, JSON의 `k8s.pod.name`은 **행위가 발생한 워크로드 Pod**를 뜻한다.

| 원본 줄 | 시나리오 / action | 실제 관찰 근거 | 이벤트 수 | 해석 |
| --- | --- | --- | ---: | --- |
| 1, 4~5 | normal / `temp_file_write` | `frontend`의 `/tmp/openmetadata-normal-session`, `/tmp/openmetadata-normal.tmp` 쓰기 | 3 | 세션 marker 생성과 임시 파일 생성·추가 쓰기 관찰 |
| 2~3 | normal / `config_read` | `cat /etc/hostname`, `cat /www/index.html` | 2 | 예상된 설정·콘텐츠 읽기 관찰 |
| 6~8 | normal / `health_check` | 같은 컨테이너 ID에서 health 응답 파일 쓰기를 세 Falco 센서가 기록 | 3 | 한 health check 행위의 중복 관측 가능성을 고려해야 함 |
| 9~10 | abnormal_1 / `credential_environment_discovery` | `backend`에서 `env`, `cat /proc/1/environ` | 2 | 환경·자격증명 탐색에 해당하는 두 명령 실행 탐지 |
| 11 | abnormal_2 / `serviceaccount_token_read` | `backend`의 `cat /var/run/secrets/kubernetes.io/serviceaccount/token`과 해당 `fd.name` | 1 | 마운트된 ServiceAccount token 경로 접근 탐지 |
| 12~13 | abnormal_3 / `payload_shell_exec` | payload 경로를 포함한 부모 `sh -c`, 자식 `sh /tmp/openmetadata-payload.sh` | 2 | 부모 명령 조건 일치와 실제 payload shell 실행 관찰 |
| 합계 | normal 8건 + abnormal 5건 | 4개 시나리오, 6개 action | 13 | 이벤트 수와 공격 횟수를 구분해 해석 |

정상 행위의 주체는 `frontend-8686cd79f6-5qw4w`의 `frontend` 및 `curl-client` 컨테이너이고, 탐색·token 접근의 주체는 `backend-675ff9dbd8-vh4sm`의 `backend` 컨테이너이다. 메타데이터가 채워진 이벤트의 namespace는 `pbl-security`이다.

[abnormal_1.sh](../../category1/abnormal_1.sh)의 credential 경로 반복문은 경로가 존재하면 `ls -l`로 확인하는 작업이다. 원본에서 확인한 두 탐지 근거를 AWS credential, SSH key, `/etc/shadow`의 실제 내용 읽기 성공으로 확대해서 설명하지 않는다. [abnormal_2.sh](../../category1/abnormal_2.sh)의 token 값은 `/dev/null`로 보내며, 로그에는 경로와 명령만 나타난다. 파일 열기 조건에 맞았다는 기록만으로 token 탈취·외부 전송이나 Kubernetes API 악용까지 입증되는 것은 아니다.

## 4. TP / TN / FP / FN 평가 방법과 초기 사례 대응

평가 단위는 원시 로그 한 줄이 아니라 **독립적으로 실행할 시나리오 1개**로 정한다. 선언한 사례 의도를 기준 정답으로 사용하고, 해당 실행 구간의 대상 컨테이너에서 커스텀 규칙의 `Warning` 이상 이벤트가 발생하면 양성으로 판정한다. 정상 확인용 `Informational`은 공격 양성이 아니다. 다음 표는 먼저 제공된 원래 4개 스크립트를 초기 수집 자료에 대응한 설명이며, 확장 평가의 지표는 7.4절에 별도로 제시한다.

| 항목 | 정의 | 이번 제공 시나리오의 제한적 대응 |
| --- | --- | --- |
| TP | 공격 모사 시나리오에서 공격 Warning 발생 | abnormal_1, abnormal_2, abnormal_3: 3개 |
| TN | 정상 시나리오에서 공격 Warning 없이 정상 활동 확인 | normal: 1개 |
| FP | 정상 시나리오를 공격 Warning으로 판정 | 제공된 정상 시나리오에서는 확인되지 않음: 0개 |
| FN | 공격 모사 시나리오에서 공격 Warning을 놓침 | 제공된 공격 시나리오에서는 확인되지 않음: 0개 |

이 표는 스크립트와 수집 명령·action을 대응한 **초기 4개 설계 사례의 결과**이다. `Warning` 5건을 TP 5개로 세지 않는다. 초기 자료에는 별도 실행 ID, 각 실행의 시작·종료 marker, 종료 코드, 독립적으로 수집한 기준 정답 자료가 없으므로 실행별 자동 평가를 완성한 결과도 아니다. 특히 커스텀 규칙만 수집한 초기 로그에서 기본 Falco 규칙의 오탐 여부는 판단할 수 없다. 이 표를 “정확도 100%”, “오탐률 0%”와 같은 일반 성능 주장으로 변환하지 않는다. 확장 평가에서는 실행 구간·종료 코드·대상 컨테이너·전체 로그를 추가로 보존했다.

## 5. 실제 관찰된 중복·메타데이터 한계

### 5.1 Health check 중복과 `<NA>`

6~8행은 컨테이너 ID `a2ae1cd0f8a5`, 파일 경로, 명령이 같고 시각도 매우 가깝지만, 센서의 `hostname`은 worker, worker2, control-plane으로 다르다. worker2 기록에는 `curl-client`와 frontend Pod 정보가 있으며, 나머지 2건의 컨테이너 이름·Pod·namespace는 null 또는 `<NA>`이다.

관찰 사실은 “동일한 컨테이너의 유사 이벤트를 세 센서가 기록했고 두 건은 메타데이터가 없다”는 것이다. kind의 노드 컨테이너가 호스트 커널을 공유하는 구성에서 센서 관찰 범위가 겹쳤을 가능성은 있지만, 이 로그만으로 원인을 확정하지 않는다. Falco는 커널을 관찰하며 컨테이너·Kubernetes 메타데이터를 별도로 보강한다. 메타데이터 조회 상태나 시점에 따라 누락이 생길 수 있다. [Falco FAQ](https://falco.org/about/faq/), [누락 필드 설명](https://falco.org/docs/troubleshooting/missing-fields/)

현재 health 규칙은 컨테이너·namespace 조건 없이 특정 응답 파일의 쓰기만 확인한다. 따라서 메타데이터가 없는 센서에서도 조건이 맞을 수 있다. 이 3건을 독립된 health check 3회 또는 공격 3회로 계산하지 않는다. 또한 shell의 리다이렉션은 `curl` 실행 전에 파일을 열 수 있으므로 이 이벤트 자체가 HTTP 응답 성공을 보증하지 않는다.

### 5.2 부모 shell과 자식 shell의 이중 조건 일치

12행의 부모 `sh -c`는 전체 명령 문자열에 payload 경로가 포함되어 있어 규칙과 일치한다. 13행에는 실제 자식 명령 `sh /tmp/openmetadata-payload.sh`가 있다. 따라서 실제 payload shell 실행 근거는 자식 명령도 함께 확인하는 것이 적절하다. 현재 조건으로는 같은 경로를 문자열로만 언급한 shell도 일치할 수 있다.

### 5.3 `file=` 출력의 의미

환경 탐색 규칙의 `file=<NA>`는 규칙 출력에 직접 작성된 값이다. 이 두 이벤트에서 파일 메타데이터 수집이 실패했다는 의미로 세지 않는다. payload 규칙의 `file=/tmp/openmetadata-payload.sh` 역시 출력 문자열의 상수이며, JSON `output_fields`에는 `fd.name`이 없다. 이 값은 파일 열기 syscall의 증거가 아니라 규칙이 설명용으로 붙인 경로이다. 반면 token 접근 이벤트에는 실제 `fd.name`이 포함된다.

## 6. 코드에서 도출한 오탐·미탐 후보와 검증 상태

초기 13개 이벤트를 검토한 뒤 규칙 코드에서 다음 후보를 도출했다. 일부는 확장 평가에서 실제 검증했고, 아직 시험하지 않은 조건은 미실행으로 구분한다. 구체적인 실제 판정과 해석은 7.4~7.5절 및 실행별 결과를 따른다.

| 종류 | 추가 검증 사례 | 코드에서 예상되는 결과와 근거 | 상태 |
| --- | --- | --- | --- |
| FP | 운영자가 정상 점검으로 backend에서 `env` 실행 | 행위 목적·사용자·변경 승인과 관계없이 `env` 조건만으로 Warning 가능 | N04 검증: 기준선 FP, V2 TN |
| FP | 권한 있는 관리자가 backend에서 token을 `cat`으로 점검 | 정당한 관리 작업도 경로와 프로세스 조건에 일치 | N07 검증: 두 규칙 모두 FP |
| FP | frontend shell이 payload 경로를 문자열로만 출력 | `proc.args contains`가 실제 실행 여부와 관계없이 일치 가능 | N05 검증: 기준선 FP, V2 TN |
| 잘못된 정상 분류 가능성 | 다른 컨테이너가 health marker 파일에 쓰기 | health 규칙에 컨테이너·namespace 제한이 없어 정상 marker 출력 가능 | 미실행 |
| FN | `cat` 대신 `head`로 환경·token 읽기 | 현재 규칙의 `proc.name=cat` 또는 `env` 제약을 벗어날 수 있음 | A03/A04 검증: 기준선 FN, V2 TP. 그 외 읽기 도구는 미실행 |
| FN | 다른 payload 파일명으로 실행 | 고정 payload 경로 조건을 벗어날 수 있음 | A06 검증: 기준선 FN, V2 TP. 다른 shell 종류는 미실행 |
| FP | 승인된 관리 스크립트를 `/tmp`에서 실행 | V2는 임시 디렉터리 실행을 정책 위반으로 경고하며 승인 여부는 알지 못함 | N06 검증: 기준선 TN, V2 FP |
| FN | shell builtin으로 이름이 바뀐 스크립트 sourcing | 새 payload 프로세스 실행이 없어 두 규칙의 실행 조건을 벗어남 | A07 검증: 두 규칙 모두 FN |
| FN | 공격자가 `env`만 실행 | V2의 Informational 정책으로 공격 Warning을 내지 않음 | A08 검증: 기준선 TP, V2 FN |
| FN 가능성 | 메타데이터 누락 또는 다른 컨테이너 이름에서 동일 행위 수행 | `container.name=frontend/backend`에 의존한 조건이 맞지 않을 수 있음 | 미실행 |
| FP / 해석 오류 가능성 | 실패한 파일 접근 또는 읽기 시도 | 현 규칙에 성공 여부를 명시한 조건이 없어 접근 시도와 성공을 구분해 확인해야 함 | 미실행 |

추가로 기준선에서 `container.name`에 의존하는 규칙에도 namespace 제한이 없으므로 다른 namespace의 동명 컨테이너가 결과에 포함될 수 있다. V2는 namespace 조건을 추가했지만, 다른 namespace를 이용한 별도 비교 실험은 실행하지 않았다. 미실행으로 표시한 조건은 코드에서 도출한 한계이며 측정된 우회 성공 사례가 아니다.

## 7. 개선 규칙 설계와 확장 평가 결과

기존 규칙을 기준선으로 보존하고, [falco-values-v2.yaml](../../category1/falco-values-v2.yaml)에 개선 규칙을 분리했다. 기준선과 개선 규칙이 같은 행위를 동시에 관찰하도록 실제 배포한 뒤 15개 사례를 실행했다. 7.1절은 설계 의도, 7.2절은 평가 방법, 7.3절은 실제 관측 결과를 구분하여 기술한다.

### 7.1 V2 설계와 예상 절충점

| 개선 규칙 | 설계 변경 | 개선하려는 문제와 남는 한계 |
| --- | --- | --- |
| `PBL V2 Sensitive File Open` | `pbl-security`의 지정 워크로드로 범위를 제한하고, 읽기 가능한 파일 열기 성공(`evt.rawres >= 0`, `evt.is_open_read`)을 프로세스 이름과 관계없이 관찰 | `cat` 이외의 읽기 도구도 포착하도록 설계했다. 파일 열기 성공은 바이트를 읽거나 외부로 전송했다는 증거는 아니며, 정당한 credential 점검도 Warning이 될 수 있다. |
| `PBL V2 Temporary Program Execution` | 임시 디렉터리의 실행 파일 또는 절대 임시 스크립트 경로로 시작하는 shell 인자를 검사하고 `execve/execveat` 성공 확인 | 부모 shell 명령 안에 경로를 언급하기만 한 경우를 줄이도록 설계했다. 옵션을 앞에 둔 shell 실행, 상대 경로, sourcing, inline 스크립트는 여전히 누락될 수 있고 정상 임시 스크립트도 Warning이 될 수 있다. |
| `PBL V2 Environment Inspection` | 지정 워크로드의 `env` 실행을 Warning 대신 Informational로 기록 | 합법적인 환경 점검 오탐을 줄이려는 변경이다. 공격자가 `env`만 실행하면 경고 양성으로 세지 않으므로, 오탐 감소와 함께 환경 탐색 단독 행위에 대한 경고 범위도 줄어든다. |

V2가 사용하는 정책은 “이 HTTP 데모 워크로드는 통상 credential 파일을 열거나 쓰기 가능한 임시 디렉터리의 프로그램을 실행하지 않는다”이다. 정책 위반 Warning과 공격 의도는 동일하지 않다. 확장 평가에서 승인된 관리 작업을 정상 정답으로 넣었으며, 이 차이로 발생하는 N06/N07 오탐도 실제 확인했다.

V2 출력에는 실제 event 시각·종류·성공 결과·프로세스와 부모 식별자·컨테이너 ID를 포함하도록 설계했다. 기준선의 `scenario` 상수와 달리 `detection`은 관찰된 행위 유형을 나타낸다. 구현만으로 메타데이터 완전성이나 탐지 개선이 검증됐다고 판단하지 않는다.

### 7.2 확장 평가 프로토콜

[evaluate.sh](../../category1/evaluate.sh)는 정상 7개·공격 모사 8개의 통제 사례를 실행하고, 각 사례의 시간 구간·대상 컨테이너 ID·의도상 정답·종료 코드와 원본 로그를 실행별 폴더에 보존한다. [analyze_results.py](../../category1/analyze_results.py)는 규칙 코드에서 예상한 결과와 실제 로그 판정을 분리한다. 본 보고서의 지표는 예상값이 아니라 실제 실행의 [summary.json](evaluation-20261110T094358Z-114177/summary.json)과 [cases.csv](evaluation-20261110T094358Z-114177/cases.csv)를 사용했다.

중요한 대조 사례는 동일한 명령에 다른 의도상 정답을 부여한 정상 환경 점검 / 공격자 환경 탐색, 승인된 token 점검 / 공격자 token 읽기이다. 이 사례들은 관찰된 명령과 파일 경로만으로 행위자의 승인 여부·의도를 완전히 구분할 수 없음을 드러내기 위해 포함했다. 승인된 임시 스크립트도 정상 정답으로 유지하여 정책 경고가 곧 공격 정답이 되지 않게 했다.

분석기는 한 사례에서 대상 컨테이너와 시간 구간이 일치하는 커스텀 Warning 이상 이벤트가 하나라도 있으면 양성으로 판정한다. 중복 센서 이벤트나 부모·자식 이벤트의 개수가 표본 수를 늘리지는 않는다. 기본 Falco 경고는 별도 집계한다. 실행 실패, 수집 불완전, 센서나 대상 컨테이너의 재시작·상태 불안정, 규칙이 실제 활성화됐는지 확인할 수 없는 경우에는 일반 FN으로 계산하지 않고 평가에서 제외하도록 설계했다. kernel event drop을 측정하지 않았으므로 무경고 결과는 해당 수집 구간의 관측 결과로만 해석한다.

다음 절차로 기준선과 개선 규칙을 비교했다.

1. 정상 관리 작업과 공격 모사를 별도 사례로 구성하고, 규칙의 `scenario` 출력과 독립적인 의도상 정답 목록을 작성했다.
2. 실행 ID, 각 사례의 시작·종료 시각, 명령 출력과 종료 코드를 기록했다. detector의 출력값을 읽어서 정답을 생성하지 않았다.
3. 같은 대상 컨테이너의 같은 실행에서 기준선과 V2를 함께 관측했다. 승인된 작업과 공격 모사에 동일 명령을 사용한 대조 사례도 유지했다.
4. 대체 읽기 도구, payload 이름 변경, sourcing과 env 단독 탐색을 실제 시험했다. 다른 shell 종류, 실패한 파일 접근과 메타데이터 누락을 강제로 유도하는 실험은 실행하지 않았다.
5. 센서별 원본 로그를 보존하고, 사례별 시간 구간과 대상 컨테이너 ID로 귀속시켰다. 동일 command 이벤트를 삭제하지 않고 원시 경고 수와 사례 수를 분리했다.
6. 센서·워크로드의 전후 상태와 수집 성공 여부를 확인한 뒤 사례 단위 TP/TN/FP/FN을 비교했다.

### 7.3 실제 실행 환경과 수집 확인

확장 평가의 실행 ID는 `evaluation-20261110T094358Z-114177`이다. 실행 구간은 UTC 2026-11-10 09:43:59~09:44:17, 한국 시각 18:43:59~18:44:17이다. 실제 설정과 수집 근거는 해당 폴더의 [run.json](evaluation-20261110T094358Z-114177/run.json), [active-helm-values.json](evaluation-20261110T094358Z-114177/active-helm-values.json), [cases.jsonl](evaluation-20261110T094358Z-114177/cases.jsonl)에 있다.

배포 기록은 chart `falco-9.2.2`, Falco `0.45.2`, Helm revision `2`, 상태 `deployed`를 나타낸다. 기준선과 V2가 모두 활성화되어 있으며 두 종류의 이벤트가 실제 수집됐다. [배포 후 release 기록](deployment-20261110T093330Z-76792/release-after.json), [배포 후 values](deployment-20261110T093330Z-76792/values-after.yaml)

현재 배포는 비교 실험을 위해 두 규칙 집합을 함께 활성화한 상태다. 아래 지표는 기준선과 V2의 경고를 각각 분리해 계산했으며, 두 집합의 모든 경고를 합친 전체 시스템의 지표가 아니다. 실제 운영에 적용하려면 채택할 규칙 집합과 기본 규칙의 경고 처리 정책을 별도로 정해야 한다.

다음 수집 확인 조건이 모두 참이었고, 모든 사례의 명령 종료 코드는 0이었다. 평가에서 제외한 사례는 없다.

| 확인 항목 | 실제 결과 |
| --- | --- |
| Falco Pod UID·Ready·재시작 수의 전후 안정성 | true |
| 필요한 모든 Falco 센서의 Ready 상태 | true |
| 원래의 모든 Falco Pod에서 로그 수집 성공 | true |
| 대상 workload Pod·컨테이너 ID·재시작 수의 전후 안정성 | true |
| kernel syscall event drop 지표 측정 | **false: 측정하지 않음** |

전체 아카이브에는 JSON 이벤트 217건이 있다. 기준선은 Informational 7건과 Warning 9건, V2는 Informational 3건과 Warning 8건이었다. 기타·기본 규칙으로 분류한 Notice 이벤트도 190건 보존되어 있다. 사례별 대상 컨테이너·시간 구간에 해당하는 기타·기본 규칙의 **Warning 이상** 집계는 모두 0건이지만, 이를 “Falco의 다른 이벤트가 전혀 없었다”는 의미로 해석하지 않는다. [센서별 전체 원본 로그](evaluation-20261110T094358Z-114177/logs), [파싱한 이벤트](evaluation-20261110T094358Z-114177/events.jsonl)

### 7.4 실제 15개 사례의 판정과 표본 지표

다음 판정은 [cases.csv](evaluation-20261110T094358Z-114177/cases.csv)의 `observed` 열에서 가져왔다. 코드에 미리 기입한 `expected` 열과 혼합하지 않았다.

| 사례 | 의도상 정답 | 실제 시험 행위 | 기준선 관측 | V2 관측 |
| --- | --- | --- | --- | --- |
| N01 | 정상 | frontend의 hostname·콘텐츠 읽기 | TN | TN |
| N02 | 정상 | frontend의 임시 텍스트 파일 생성·수정·읽기 | TN | TN |
| N03 | 정상 | curl-client의 loopback HTTP health check | TN | TN |
| N04 | 정상 | 승인된 관리자의 backend `env` 실행 | FP | TN |
| N05 | 정상 | payload 경로 문자열만 출력하고 실행하지 않음 | FP | TN |
| N06 | 정상 | `/tmp`의 승인된 관리 스크립트 실행 | TN | FP |
| N07 | 정상 | 승인된 관리자의 `cat` token 점검, 내용 폐기 | FP | FP |
| A01 | 공격 모사 | `env`와 `/proc/1/environ` 조회 | TP | TP |
| A02 | 공격 모사 | `cat`으로 token 읽기, 내용 폐기 | TP | TP |
| A03 | 공격 모사 | `head`로 token 읽기, 내용 폐기 | FN | TP |
| A04 | 공격 모사 | `head`로 `/proc/1/environ` 읽기 | FN | TP |
| A05 | 공격 모사 | 원래 고정 이름의 로컬 payload marker 실행 | TP | TP |
| A06 | 공격 모사 | 이름을 바꾼 `/tmp` payload marker 실행 | FN | TP |
| A07 | 공격 모사 | 이름을 바꾼 스크립트를 shell builtin으로 sourcing | FN | FN |
| A08 | 공격 모사 | 공격자가 `env`만 실행 | TP | FN |

| 규칙 | TP | TN | FP | FN | 평가 사례 | 제외 | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 기준선 | 4 | 4 | 3 | 4 | 15 | 0 | 57.1% | 50.0% | 42.9% |
| V2 | 6 | 5 | 2 | 2 | 15 | 0 | 75.0% | 75.0% | 28.6% |

계산식은 Precision = TP / (TP + FP), Recall = TP / (TP + FN), FPR = FP / (FP + TN)이다. FPR의 분모는 정상 사례 7개, Recall의 분모는 공격 모사 사례 8개이다. 원시 Warning 개수는 이 분모에 사용하지 않았다. 이 비율은 **이번 15개 통제 사례에 한정된 관측 지표**이다. V2와 시험 사례를 함께 수동 설계했고 1회만 실행했으므로, 독립된 holdout·반복 데이터에 의한 평가나 편향 없는 운영 성능 추정이 아니다. 정상·공격 의도는 사례 작성자의 선언이며 외부 행위자·승인 상태를 독립적으로 검증한 정답이 아니다.

### 7.5 개선 효과와 남은 오탐·미탐의 해석

기준선의 대체 읽기 도구 미탐 A03/A04와 이름 변경 미탐 A06은 V2에서 TP로 바뀌었다. 프로세스 이름 대신 민감 파일의 읽기 가능한 열기 성공을 보는 조건, 고정 파일명 대신 임시 디렉터리의 프로그램 실행을 보는 조건이 이 사례에서 효과를 냈다. V2의 파일 이벤트는 성공한 read-capable open을 입증하며, 그 이벤트만으로 실제 내용 소비·탈취·외부 전송을 입증하지 않는다.

정상 환경 점검 N04와 경로 문자열 출력 N05는 기준선 FP에서 V2 TN으로 바뀌었다. 그러나 승인된 임시 스크립트 N06은 새로 V2 FP가 되었고, 승인된 token 점검 N07은 두 규칙 모두 FP였다. 따라서 정상 7개 중 오탐 수는 3개에서 2개로 순감소했지만, 모든 종류의 정상 작업에서 일관되게 개선된 것은 아니다.

`env`를 문맥용 Informational로 바꾼 결과, 공격자 `env` 단독 사례 A08은 기준선 TP에서 V2 FN으로 바뀌었다. 복합 탐색 A01은 민감 파일 접근 때문에 여전히 TP지만, 이것만 보고 환경 탐색 전반이 유지됐다고 판단하면 안 된다. 정상 N04와 공격 모사 A08은 실제 명령이 같고, 정상 N07과 공격 모사 A02도 실제 명령이 같다. 현재 관찰 정보만으로 승인·의도 차이를 완전히 구분할 수 없음을 직접 보여준다.

두 규칙이 모두 놓친 A07은 새 payload 프로세스를 만들지 않고 shell builtin으로 스크립트를 source한 사례다. V2의 실행 중심 조건 범위 밖이므로 FN이 남았다. 향후 파일 읽기·프로세스·출처·승인 맥락을 함께 보는 후속 규칙 후보이지만, 그 개선 규칙을 구현·검증한 결과는 이번 자료에 없다.

추가 한계는 kernel event drop을 측정하지 않았다는 점이다. 센서와 수집 상태가 안정적이었고 예상된 양성 대조군도 수집됐으나, 무경고 사례의 모든 syscall이 손실 없이 처리됐다고 보증할 수 없다. 동일 컨테이너의 동시 작업이나 클라이언트·커널 시계 차이도 시간 구간 귀속을 방해할 수 있다. 정답은 명시한 시험 의도이며 독립적인 실사고 판정이 아니다. 실제 서비스 부하, 다른 애플리케이션, 다른 shell·경로·실패 접근, 다른 namespace와 반복 실행은 추가 검증 대상이다.

### 7.6 수집·재현 및 복원

실제 확장 평가기는 센서별로 `kubectl logs --since-time=... --tail=-1`을 사용했다. label selector를 쓰는 간단 조회에서도 `--tail=-1`을 명시해야 한다. selector가 있으면 기본값이 최근 10줄이므로 수집 누락이 탐지 미탐처럼 보일 수 있다. [공식 kubectl logs 설명](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_logs/)

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco \
  -c falco --prefix --since=10m --tail=-1 \
  | grep -E 'PBL(_V2)?_EVENT'
```

위 명령은 간단 확인용 예시이며, 초기 13건 원본이 이 옵션으로 수집됐다고 단정하지 않는다. 원본 파일을 덮어쓰지 않고 별도 실행 결과로 저장해야 비교 근거를 유지할 수 있다. 전체 사례 재현에는 `bash category1/evaluate.sh`를 사용하며, 분석만 다시 수행하려면 다음과 같이 실행한다.

```bash
python3 category1/analyze_results.py \
  results/category1/evaluation-20261110T094358Z-114177
```

[apply-v2.sh](../../category1/apply-v2.sh)는 기존 chart 버전을 유지하고 `--reuse-values`로 커스텀 규칙을 추가하며, 배포 전후 values와 revision을 별도 폴더에 기록한다. 이번 배포 전 revision은 1이다. V2를 적용하기 전 설정으로 되돌려야 할 때 사용할 명령은 다음과 같다. 이 보고서 작성 과정에서 복원 명령을 실행하지는 않았다.

```bash
helm rollback falco 1 --namespace falco --wait --timeout 10m
```

## 8. 재현 자료

- 초기 측정 원본: [제공된 스크립트 실행의 전체 13개 이벤트](falco-events.log)
- 확장 평가: [15개 사례 결과와 사례별 근거](evaluation-20261110T094358Z-114177/summary.md), [summary.json](evaluation-20261110T094358Z-114177/summary.json), [cases.csv](evaluation-20261110T094358Z-114177/cases.csv)
- 확장 평가 원본: [실행 정답·시간·종료 코드](evaluation-20261110T094358Z-114177/cases.jsonl), [센서별 로그](evaluation-20261110T094358Z-114177/logs), [실행별 명령 출력](evaluation-20261110T094358Z-114177/commands)
- 소스 보존: [평가 소스 사본](evaluation-20261110T094358Z-114177/sources), [SHA256와 보존 시점](evaluation-20261110T094358Z-114177/sources/provenance.json). 이번 사본은 평가 완료 후 보존했다고 표시했다. 평가 당시 실제 배포 규칙의 근거는 `active-helm-values.json`이다. 이후 실행기는 사례 실행 전에 소스 사본과 해시를 자동 보존한다.
- 기준선 규칙: [category1/falco-values.yaml](../../category1/falco-values.yaml)
- 정상 기준선: [normal.sh](../../category1/normal.sh)
- 공격 모사: [환경 탐색](../../category1/abnormal_1.sh), [token 접근](../../category1/abnormal_2.sh), [payload shell 실행](../../category1/abnormal_3.sh)
- 설치 설정: [install.sh](../../install.sh)
- 개선·평가 도구: [V2 규칙](../../category1/falco-values-v2.yaml), [배포 스크립트](../../category1/apply-v2.sh), [실험 실행기](../../category1/evaluate.sh), [분석기](../../category1/analyze_results.py)
- 배포 근거: [초기 release](deployment-20261110T093330Z-76792/release-before.json), [배포 후 release](deployment-20261110T093330Z-76792/release-after.json), [배포 후 values](deployment-20261110T093330Z-76792/values-after.yaml)
- 프로젝트의 사전 로그 예시는 [category1/logs](../../category1/logs)에 있다. 이 보고서의 초기 13건 집계는 `results/category1/falco-events.log`, 확장 15개 사례 지표는 위 실행별 폴더를 사용했다. 사전 예시나 일부를 붙여 넣은 첨부를 측정 자료에 합산하지 않았다.
