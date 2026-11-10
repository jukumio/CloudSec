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
  -c falco --prefix --follow --tail=0 \
  | grep --line-buffered -E 'PBL(_V2)?_EVENT'
```

Terminal 2:

```bash
cd Practical-Cloud-Security-PBL
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh
```

Recent events:

```bash
kubectl logs -n falco \
  -l app.kubernetes.io/name=falco \
  -c falco --prefix --since=10m --tail=-1 \
  | grep -E 'PBL(_V2)?_EVENT'
```

Normal events represent expected configuration and temporary-file activity. Abnormal events have distinct discovery, token-read, and payload-execution `action` values. See `logs/normal.log` and `logs/abnormal_1.log` through `abnormal_3.log`.

## Detection Design and False-positive / False-negative Evaluation

The [results report](../results/category1/report.md) documents detection evidence, observed results, false positives, false negatives, and limitations. After verifying the provided scenarios, use the extended evaluation to test how the rules distinguish normal work from modified attack simulations.

Compare the [baseline rules](falco-values.yaml) and [supplemental V2 rules](falco-values-v2.yaml) against the same actions. V2 limits scope by namespace and container role, reduces dependence on a particular reader program or payload filename, and records `env` alone as informational context. Authorized maintenance can produce the same file and process behavior as an attacker, so a warning identifies activity to investigate rather than proving malicious intent.

Run these commands in order from the project root after the common installation completes. The [deployment script](apply-v2.sh) checks the `kind-pbl-security` context, pins the currently installed Helm chart version, renders the upgrade first, and deploys with `--atomic`. It preserves the baseline rules and records the before/after values and a rollback command for the previous revision. Run the evaluation only after deployment succeeds.

```bash
bash category1/apply-v2.sh
bash category1/evaluate.sh
```

The [evaluation script](evaluate.sh) runs 15 controlled cases: 7 benign actions and 8 safe attack simulations. These include normal environment inspection, merely printing a path, authorized temporary scripts and token access, plus alternate readers such as `head`, renamed payloads, and shell sourcing. Token and environment contents are discarded. Ground truth comes from the declared purpose of each experiment, not from Falco independently knowing the actor's intent.

Deployment evidence goes to a new `results/category1/deployment-<UTC>-<pid>/` directory; evaluation evidence goes to `results/category1/evaluation-<UTC>-<pid>/`. The [analyzer](analyze_results.py) runs automatically after the evaluation.

| Evaluation artifact | Contents |
| --- | --- |
| `cases.jsonl`, `commands/` | Declared purpose, command exit status, time window, target container, stdout and stderr |
| `logs/`, `active-helm-values.json` | Full original Falco logs and active rule configuration |
| `cases.csv` | Expected and observed baseline/V2 TP, TN, FP and FN for each case |
| `summary.md`, `summary.json`, `events.jsonl` | Collection checks, case evidence, metrics and parsed events |

One completed case is one sample. Duplicate observations by multiple agents or parent/child processes do not increase the attack count. Scores compare only Warning-or-higher alerts from the PBL baseline and V2 rules. Default and other Falco alerts are archived and listed separately; a PBL custom-rule miss does not imply that all Falco rules missed it.

Failed commands, restarted collectors, and incomplete collection are excluded or marked unverified. A case without an alert is an observed non-match within a finite capture window. Event-drop metrics are not measured, so zero loss cannot be assumed, and rates from this small suite must not be generalized to production accuracy. See the report for the classification rationale and remaining false-positive and false-negative risks.
