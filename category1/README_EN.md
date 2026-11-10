# Category 1: OpenMetadata Attack (2024)

[한국어](README.md) | **English**

## Real Incident

In 2024, attackers exploited remote-code-execution vulnerabilities in OpenMetadata deployments running on Kubernetes. Post-compromise activity included system reconnaissance, environment and credential discovery, followed by payload and shell execution. See the [2024 Microsoft Threat Intelligence analysis](https://www.microsoft.com/en-us/security/blog/2024/04/17/attackers-exploiting-new-critical-openmetadata-vulnerabilities-on-kubernetes-clusters/).

> This lab does not reproduce malware or create an external reverse shell. It safely simplifies the file and process behaviors needed to generate detectable Falco evidence.

## Attack Mapping

| Script | Real attack phase | Safe lab behavior | Falco discriminator |
| --- | --- | --- | --- |
| `normal.sh` | Administrative baseline | `sh`, `cat`, `curl`, config reads, `/tmp` activity, health check | `scenario=normal` |
| `abnormal_1.sh` | Reconnaissance and credential discovery | Inspect environment, `/proc/1/environ`, and common credential paths | `scenario=abnormal_1` |
| `abnormal_2.sh` | Kubernetes credential access | Read the mounted ServiceAccount token | `scenario=abnormal_2` |
| `abnormal_3.sh` | Payload and shell execution | Execute a local payload marker with no network connection | `scenario=abnormal_3` |

## Run and Observe

Terminal 1:

```bash
kubectl logs -n falco \
  -l app.kubernetes.io/name=falco \
  -c falco --prefix --follow | grep --line-buffered PBL_EVENT
```

Terminal 2:

```bash
cd pbl-project
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh
```

Normal events represent expected configuration and temporary-file activity. Abnormal events have distinct discovery, token-read, and payload-execution `action` values. See `logs/normal.log` and `logs/abnormal_1.log` through `abnormal_3.log`.
