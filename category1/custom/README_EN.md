# Category 1 Custom Detection and Extended Evaluation

[한국어](README.md) | **English**

This folder contains the added implementation and documentation. Provided rules and scenarios remain in the parent `category1/` directory. Original run artifacts and source snapshots remain in `results/category1/` at the repository root.

| File | Purpose |
| --- | --- |
| [falco-values-v2.yaml](falco-values-v2.yaml) | V2 detection rules |
| [apply-v2.sh](apply-v2.sh) | Deploy V2 to the existing lab |
| [evaluate.sh](evaluate.sh) | Run 7 benign and 8 simulated attack cases |
| [analyze_results.py](analyze_results.py) | Analyze logs and calculate metrics |
| [report.md](report.md) | Measured results and false-positive/false-negative analysis |

## Detection Design and False-positive / False-negative Evaluation

The [results report](report.md) documents detection evidence, observed results, false positives, false negatives, and limitations. After verifying the provided scenarios, use the extended evaluation to test how the rules distinguish normal work from modified attack simulations.

Compare the [baseline rules](../falco-values.yaml) and [supplemental V2 rules](falco-values-v2.yaml) against the same actions. V2 limits scope by namespace and container role, reduces dependence on a particular reader program or payload filename, and records `env` alone as informational context. Authorized maintenance can produce the same file and process behavior as an attacker, so a warning identifies activity to investigate rather than proving malicious intent.

Run these commands in order from the project root after the common installation completes. The [deployment script](apply-v2.sh) checks the `kind-pbl-security` context, pins the currently installed Helm chart version, renders the upgrade first, and deploys with `--atomic`. It preserves the baseline rules and records the before/after values and a rollback command for the previous revision. Run the evaluation only after deployment succeeds.

```bash
bash category1/custom/apply-v2.sh
bash category1/custom/evaluate.sh
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
