# Category 3: Cryptocurrency Platform Kubernetes Incident (2025)

[한국어](README.md) | **English**

## Real Incident

In a 2025 cryptocurrency-platform Kubernetes incident, an attacker used acquired workload ServiceAccount credentials to call the Kubernetes API, enumerate Secrets and resources, and attempt access to another workload. Kubernetes can project ServiceAccount tokens into Pods by default, making least-privilege RBAC important. See the [Kubernetes ServiceAccount documentation](https://kubernetes.io/docs/concepts/security/service-accounts/).

> This lab does not steal real Secrets or execute commands in another Pod. It safely simplifies the behavior by using one low-privilege ServiceAccount for both allowed baseline requests and denied attack-like requests.

Every script uses the same `pbl-crypto-platform-app` ServiceAccount. It can only `get/list` Pods, Services, and ConfigMaps; it cannot read Secrets or create `pods/exec`.

## Attack Mapping

| Script | Real attack phase | API behavior | Audit Log evidence |
| --- | --- | --- | --- |
| `normal.sh` | Normal application API use | Query pods/services/configmaps | Same user, `get/list`, `code=200` |
| `abnormal_1.sh` | Secret enumeration | `list` secrets | Same user, resource=secrets, `code=403` |
| `abnormal_2.sh` | Access another workload | `create` pods/exec | Same user, subresource=exec, `code=403` |
| `abnormal_3.sh` | Bulk resource enumeration | Repeated pods/secrets/configmaps queries | Same user, broader resources and sharply higher frequency |

## Run and Observe

Terminal 1:

```bash
docker exec pbl-security-control-plane \
  tail -F /var/log/kubernetes/audit.log | \
grep --line-buffered pbl-crypto-platform-app
```

Terminal 2:

```bash
cd pbl-project
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

See `logs/normal.log` and `logs/abnormal_1.log` through `abnormal_3.log` for representative events.
