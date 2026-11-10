# Category 1 결과 보고서: Pod 내부 행위 탐지와 정상·공격 구분

## 1. 결론과 평가 범위

기존 Falco 커스텀 규칙으로 정상 기준선 1개와 공격 모사 시나리오 3개를 구분하는 동작을 확인했다. 실제 수집 파일 [falco-events.log](falco-events.log)의 13개 이벤트에는 정상 `Informational` 8건과 공격 모사 `Warning` 5건이 있으며, 설계한 6개 `action`이 모두 포함된다.

이 결과는 **제공된 정상·공격 모사 스크립트에 대한 기준선 검증 성공**이다. 정상·비정상이라는 표시는 규칙 작성자가 정한 조건과 출력값이며, Falco가 행위의 악성 여부를 독립적으로 판정한 결과는 아니다. 다양한 정상 업무와 변형 공격을 검증하지 않았으므로 운영 환경의 탐지 정확도나 오탐률을 입증한 결과로 해석하지 않는다.

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

[설치 스크립트](../../install.sh)는 Falco를 배포하고 JSON 출력, `rule_matching=all`, [커스텀 규칙 파일](../../category1/falco-values.yaml)을 설정한다. `rule_matching=all`에서는 기본 규칙과 커스텀 규칙이 함께 결과를 낼 수 있다. 이번 결과 파일은 `PBL_EVENT`에 해당하는 실습 규칙 출력이며, Falco의 모든 경고를 포함하는 자료로 간주하지 않는다.

| 시나리오 | 규칙이 실제로 확인하는 조건 | 출력 action | 우선순위 |
| --- | --- | --- | --- |
| 정상 설정 읽기 | `frontend`의 `cat`이 `/etc/hostname` 또는 `/www/index.html`을 `open/openat/openat2`로 접근 | `config_read` | Informational |
| 정상 임시 파일 작업 | `frontend`가 `/tmp/openmetadata-normal`로 시작하는 파일을 쓰기 모드로 열기 | `temp_file_write` | Informational |
| 정상 health check | 컨테이너가 `/tmp/openmetadata-health-response`를 쓰기 모드로 열기 | `health_check` | Informational |
| 공격 모사 1 | `backend`에서 `env` 실행 또는 인자에 `/proc/1/environ`을 포함한 `cat` 실행 | `credential_environment_discovery` | Warning |
| 공격 모사 2 | `backend`의 `cat`이 경로에 `kubernetes.io/serviceaccount`를 포함하고 `token`으로 끝나는 파일을 열기 | `serviceaccount_token_read` | Warning |
| 공격 모사 3 | `frontend`에서 `/tmp/openmetadata-payload.sh`가 인자에 포함된 `sh` 실행 | `payload_shell_exec` | Warning |

정상 시나리오도 shell과 `cat`을 사용한다. 따라서 단순히 “shell 실행”이나 “cat 사용”만으로 공격이라고 분류하지 않고, 컨테이너 역할, 접근 대상, 명령 인자를 결합한다. 다만 현재 조건은 실습에서 정한 컨테이너 이름과 경로에 맞춰져 있으며, 일반적인 공격 전체를 포괄하지 않는다. Falco의 조건·출력·우선순위 구분은 [공식 규칙 설명](https://falco.org/docs/concepts/rules/basic-elements/)을 참고했다.

## 3. 실제 수집 결과와 판단 근거

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

## 4. TP / TN / FP / FN 평가 방법

평가 단위는 원시 로그 한 줄이 아니라 **독립적으로 실행할 시나리오 1개**로 정한다. 제공된 스크립트의 의도를 기준 정답으로 사용하고, 해당 실행 구간에서 커스텀 공격 규칙의 `Warning`이 발생하면 양성으로 판정한다. 정상 확인용 `Informational`은 공격 양성이 아니다.

| 항목 | 정의 | 이번 제공 시나리오의 제한적 대응 |
| --- | --- | --- |
| TP | 공격 모사 시나리오에서 공격 Warning 발생 | abnormal_1, abnormal_2, abnormal_3: 3개 |
| TN | 정상 시나리오에서 공격 Warning 없이 정상 활동 확인 | normal: 1개 |
| FP | 정상 시나리오를 공격 Warning으로 판정 | 제공된 정상 시나리오에서는 확인되지 않음: 0개 |
| FN | 공격 모사 시나리오에서 공격 Warning을 놓침 | 제공된 공격 시나리오에서는 확인되지 않음: 0개 |

이 표는 스크립트와 수집 명령·action을 대응한 **4개 설계 사례의 결과**이다. `Warning` 5건을 TP 5개로 세지 않는다. 현재 자료에는 별도 실행 ID, 각 실행의 시작·종료 marker, 종료 코드, 독립적으로 수집한 기준 정답 자료가 없으므로 실행별 자동 평가를 완성한 결과도 아니다. 특히 커스텀 규칙만 수집한 로그에서 기본 Falco 규칙의 오탐 여부는 판단할 수 없다. 이 표를 “정확도 100%”, “오탐률 0%”와 같은 일반 성능 주장으로 변환하지 않는다.

## 5. 실제 관찰된 중복·메타데이터 한계

### 5.1 Health check 중복과 `<NA>`

6~8행은 컨테이너 ID `a2ae1cd0f8a5`, 파일 경로, 명령이 같고 시각도 매우 가깝지만, 센서의 `hostname`은 worker, worker2, control-plane으로 다르다. worker2 기록에는 `curl-client`와 frontend Pod 정보가 있으며, 나머지 2건의 컨테이너 이름·Pod·namespace는 null 또는 `<NA>`이다.

관찰 사실은 “동일한 컨테이너의 유사 이벤트를 세 센서가 기록했고 두 건은 메타데이터가 없다”는 것이다. kind의 노드 컨테이너가 호스트 커널을 공유하는 구성에서 센서 관찰 범위가 겹쳤을 가능성은 있지만, 이 로그만으로 원인을 확정하지 않는다. Falco는 커널을 관찰하며 컨테이너·Kubernetes 메타데이터를 별도로 보강한다. 메타데이터 조회 상태나 시점에 따라 누락이 생길 수 있다. [Falco FAQ](https://falco.org/about/faq/), [누락 필드 설명](https://falco.org/docs/troubleshooting/missing-fields/)

현재 health 규칙은 컨테이너·namespace 조건 없이 특정 응답 파일의 쓰기만 확인한다. 따라서 메타데이터가 없는 센서에서도 조건이 맞을 수 있다. 이 3건을 독립된 health check 3회 또는 공격 3회로 계산하지 않는다. 또한 shell의 리다이렉션은 `curl` 실행 전에 파일을 열 수 있으므로 이 이벤트 자체가 HTTP 응답 성공을 보증하지 않는다.

### 5.2 부모 shell과 자식 shell의 이중 조건 일치

12행의 부모 `sh -c`는 전체 명령 문자열에 payload 경로가 포함되어 있어 규칙과 일치한다. 13행에는 실제 자식 명령 `sh /tmp/openmetadata-payload.sh`가 있다. 따라서 실제 payload shell 실행 근거는 자식 명령도 함께 확인하는 것이 적절하다. 현재 조건으로는 같은 경로를 문자열로만 언급한 shell도 일치할 수 있다.

### 5.3 `file=` 출력의 의미

환경 탐색 규칙의 `file=<NA>`는 규칙 출력에 직접 작성된 값이다. 이 두 이벤트에서 파일 메타데이터 수집이 실패했다는 의미로 세지 않는다. payload 규칙의 `file=/tmp/openmetadata-payload.sh` 역시 출력 문자열의 상수이며, JSON `output_fields`에는 `fd.name`이 없다. 이 값은 파일 열기 syscall의 증거가 아니라 규칙이 설명용으로 붙인 경로이다. 반면 token 접근 이벤트에는 실제 `fd.name`이 포함된다.

## 6. 예상 오탐·미탐 분석: 아직 측정하지 않은 가설

다음은 규칙 코드를 읽고 도출한 예상이다. 현재 13개 이벤트에서 측정한 오탐·미탐 수치와 구분하며, 개선 전후 비교 실험을 실행하기 전까지 검증 대기로 둔다.

| 종류 | 추가 검증 사례 | 코드에서 예상되는 결과와 근거 | 상태 |
| --- | --- | --- | --- |
| FP 가능성 | 운영자가 정상 점검으로 backend에서 `env` 실행 | 행위 목적·사용자·변경 승인과 관계없이 `env` 조건만으로 Warning 가능 | 미실행 |
| FP 가능성 | 권한 있는 관리자가 backend에서 token을 `cat`으로 점검 | 정당한 관리 작업도 경로와 프로세스 조건에 일치 | 미실행 |
| FP 가능성 | frontend shell이 payload 경로를 문자열로만 출력 | `proc.args contains`가 실제 실행 여부와 관계없이 일치 가능 | 미실행 |
| 잘못된 정상 분류 가능성 | 다른 컨테이너가 health marker 파일에 쓰기 | health 규칙에 컨테이너·namespace 제한이 없어 정상 marker 출력 가능 | 미실행 |
| FN 가능성 | `cat` 대신 `head`, 다른 도구 또는 프로그램으로 환경·token 읽기 | 현재 규칙의 `proc.name=cat` 또는 `env` 제약을 벗어날 수 있음 | 미실행 |
| FN 가능성 | 다른 shell 또는 다른 payload 파일명으로 실행 | `proc.name=sh`와 고정 payload 경로 조건을 벗어날 수 있음 | 미실행 |
| FN 가능성 | 메타데이터 누락 또는 다른 컨테이너 이름에서 동일 행위 수행 | `container.name=frontend/backend`에 의존한 조건이 맞지 않을 수 있음 | 미실행 |
| FP / 해석 오류 가능성 | 실패한 파일 접근 또는 읽기 시도 | 현 규칙에 성공 여부를 명시한 조건이 없어 접근 시도와 성공을 구분해 확인해야 함 | 미실행 |

추가로 `container.name`에 의존하는 규칙에도 namespace 제한이 없으므로 다른 namespace의 동명 컨테이너가 결과에 포함될 수 있다. 위의 예상은 실습 범위를 넓힐 때 검증할 항목이며, 현재 자료에서 실제 우회 공격이 성공했다는 주장이 아니다.

## 7. 개선안과 후속 실험 계획

현재 규칙을 기준선으로 보존하고, 개선 규칙은 별도 파일·별도 실행 결과로 비교한다. 개선 규칙 파일과 확장 테스트의 최종 이름은 후속 구현에서 확정한다. **본 보고서 작성 시점에는 개선 규칙 적용 및 확장 테스트를 실행하지 않았다.**

1. 정상 관리 작업과 공격 모사를 별도 사례로 구성하고, 규칙의 `scenario` 출력과 독립적인 기준 정답 목록을 작성한다.
2. 각 사례의 실행 ID, 시작·종료 시각, 실제 명령, 종료 코드를 기록한다. 정답은 스크립트 이름이나 Falco 출력값을 그대로 다시 읽어 생성하지 않는다.
3. namespace·Pod 역할 범위를 명확히 하고, payload는 부모 명령의 문자열 포함과 실제 자식 실행을 구분한다. 합법적인 환경 조회를 예외로 둘 때에는 단순 프로세스명 전체 허용으로 공격을 숨기지 않도록 역할·실행 맥락과 함께 검증한다.
4. 대체 파일 읽기 도구와 payload 경로·shell 변경을 시험하여 과도하게 좁은 조건의 미탐을 확인한다. 성공한 접근과 실패한 시도도 구분한다.
5. 로그 원본은 보존하고, 분석 단계에서 센서 간 중복 후보와 부모·자식 이벤트를 표시한다. 동일 command만으로 무조건 제거하지 말고 컨테이너 ID·행위·시각 및 가능한 프로세스 식별자를 함께 대조한다.
6. 동일한 평가 사례에 기준선과 개선 규칙을 각각 적용한 뒤 사례 단위 TP/TN/FP/FN, 중복 수, 메타데이터 누락 수를 비교한다. 기준선에서 이미 관찰된 결과와 새로 측정한 결과를 분리한다.

후속 수집에서는 label selector를 쓰는 `kubectl logs`에 `--tail=-1`을 명시한다. selector가 있으면 기본값이 최근 10줄이므로 수집 누락이 탐지 미탐처럼 보일 수 있다. [공식 kubectl logs 설명](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_logs/)

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco \
  -c falco --prefix --since=10m --tail=-1 \
  | grep PBL_EVENT
```

이 명령은 후속 수집 예시이며, 기존 원본이 이 옵션으로 수집됐다고 단정하지 않는다. 원본 파일을 덮어쓰지 않고 별도 결과로 저장해야 비교 근거를 유지할 수 있다.

## 8. 재현 자료

- 측정 원본: [이번 실행의 전체 13개 이벤트](falco-events.log)
- 기준선 규칙: [category1/falco-values.yaml](../../category1/falco-values.yaml)
- 정상 기준선: [normal.sh](../../category1/normal.sh)
- 공격 모사: [환경 탐색](../../category1/abnormal_1.sh), [token 접근](../../category1/abnormal_2.sh), [payload shell 실행](../../category1/abnormal_3.sh)
- 설치 설정: [install.sh](../../install.sh)
- 프로젝트의 사전 로그 예시는 [category1/logs](../../category1/logs)에 있다. 이 보고서의 측정 건수는 사전 예시나 일부를 붙여 넣은 첨부가 아니라 `results/category1/falco-events.log`만 사용했다.
