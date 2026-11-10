# Category 3: Cryptocurrency Platform Kubernetes Incident (2025)

**한국어** | [English](README_EN.md)

## 실제 사례

2025년 암호화폐 플랫폼 Kubernetes 침해 사례에서는 workload에서 획득한 ServiceAccount credential로 Kubernetes API를 호출하고, Secret과 리소스를 열거한 뒤 다른 workload 접근을 시도하는 post-compromise 흐름이 확인됐습니다. Kubernetes에서는 Pod에 ServiceAccount token이 기본적으로 투영될 수 있으므로 최소 권한 RBAC가 중요합니다. 동작 원리는 [Kubernetes ServiceAccount 문서](https://kubernetes.io/docs/concepts/security/service-accounts/)를 참고합니다.

> 이 실습은 실제 Secret을 탈취하거나 다른 Pod에 명령을 실행하지 않습니다. 동일한 저권한 ServiceAccount가 허용된 조회와 거부되는 공격성 요청을 보내도록 안전하게 단순화합니다.

모든 스크립트는 동일한 `pbl-crypto-platform-app` ServiceAccount를 사용합니다. 이 계정은 Pods, Services, ConfigMaps의 `get/list`만 허용되고 Secrets 및 `pods/exec` 권한은 없습니다.

## 공격 행위 대응

| 스크립트 | 실제 공격 단계 | API 행위 | Audit Log 관찰점 |
| --- | --- | --- | --- |
| `normal.sh` | 정상 애플리케이션 API 사용 | pods/services/configmaps 조회 | 같은 사용자, `get/list`, `code=200` |
| `abnormal_1.sh` | Secret enumeration | secrets `list` | 같은 사용자, resource=secrets, `code=403` |
| `abnormal_2.sh` | 다른 workload 접근 | pods/exec `create` | 같은 사용자, subresource=exec, `code=403` |
| `abnormal_3.sh` | 대량 resource enumeration | pods/secrets/configmaps 반복 조회 | 같은 사용자, resource 다양화와 빈도 급증 |

## 실행 및 로그

터미널 1:

```bash
docker exec pbl-security-control-plane \
  tail -F /var/log/kubernetes/audit.log | \
grep --line-buffered pbl-crypto-platform-app
```

터미널 2:

```bash
cd pbl-project
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

최근 이벤트:

```bash
docker exec pbl-security-control-plane \
  grep 'pbl-crypto-platform-app' /var/log/kubernetes/audit.log | tail -n 50
```

예시는 `logs/normal.log`, `logs/abnormal_1.log`부터 `abnormal_3.log`까지 확인합니다.
