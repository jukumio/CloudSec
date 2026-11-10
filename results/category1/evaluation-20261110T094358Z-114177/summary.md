# Category 1 controlled evaluation

## Measurement scope

One completed test case is one sample. Multiple agents/events do not increase the sample count.
An alert means a Warning-or-higher custom rule matched within the case window and target container.
Default Falco alerts are archived and listed separately; a custom-rule miss is not a claim that all Falco rules missed.
Ground truth is the declared scenario intent. An authorized temporary script and an attacker script can look identical.

## Collection checks

- stable_falco_pods: `true`
- all_desired_agents_ready: `true`
- all_logs_collected: `true`
- stable_workload_containers: `true`
- event_drop_metrics_checked: `false`

## Observed case results

Expected outcomes are code-derived hypotheses; observed outcomes come only from the captured logs.

| Case | Ground truth | Command exit | Baseline expected / observed | V2 expected / observed | Raw custom alerts base / v2 |
|---|---|---:|---|---|---:|
| N01 | benign | 0 | TN / TN | TN / TN | 0 / 0 |
| N02 | benign | 0 | TN / TN | TN / TN | 0 / 0 |
| N03 | benign | 0 | TN / TN | TN / TN | 0 / 0 |
| N04 | benign | 0 | FP / FP | TN / TN | 1 / 0 |
| N05 | benign | 0 | FP / FP | TN / TN | 1 / 0 |
| N06 | benign | 0 | TN / TN | FP / FP | 0 / 1 |
| N07 | benign | 0 | FP / FP | FP / FP | 1 / 1 |
| A01 | attack | 0 | TP / TP | TP / TP | 2 / 1 |
| A02 | attack | 0 | TP / TP | TP / TP | 1 / 1 |
| A03 | attack | 0 | FN / FN | TP / TP | 0 / 1 |
| A04 | attack | 0 | FN / FN | TP / TP | 0 / 1 |
| A05 | attack | 0 | TP / TP | TP / TP | 2 / 1 |
| A06 | attack | 0 | FN / FN | TP / TP | 0 / 1 |
| A07 | attack | 0 | FN / FN | FN / FN | 0 / 0 |
| A08 | attack | 0 | TP / TP | FN / FN | 1 / 0 |

## Sample metrics

These rates describe only this small controlled suite, not production detection accuracy.

| Detector | TP | TN | FP | FN | Evaluated | Excluded | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 4 | 4 | 3 | 4 | 15 | 0 | 0.571 | 0.500 | 0.429 |
| v2 | 6 | 5 | 2 | 2 | 15 | 0 | 0.750 | 0.750 | 0.286 |

## Case evidence

### N01: Routine configuration reads

- Ground truth: `benign`; pod: `frontend-8686cd79f6-5qw4w`; container: `frontend`.
- Window (Unix nanoseconds): `1794303839312250069` through `1794303839528342557`.
- Baseline matching rules: PBL Normal Configuration Read.
- V2 matching rules: (none observed).
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/N01.stdout), [stderr](commands/N01.stderr).

### N02: Routine temporary text file operations

- Ground truth: `benign`; pod: `frontend-8686cd79f6-5qw4w`; container: `frontend`.
- Window (Unix nanoseconds): `1794303840555462118` through `1794303840774683425`.
- Baseline matching rules: PBL Normal Temporary File Activity.
- V2 matching rules: (none observed).
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/N02.stdout), [stderr](commands/N02.stderr).

### N03: Loopback HTTP health check

- Ground truth: `benign`; pod: `frontend-8686cd79f6-5qw4w`; container: `curl-client`.
- Window (Unix nanoseconds): `1794303841801786578` through `1794303842039143775`.
- Baseline matching rules: PBL Normal Curl Health Check.
- V2 matching rules: (none observed).
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/N03.stdout), [stderr](commands/N03.stderr).

### N04: Authorized administrator inspects environment

- Ground truth: `benign`; pod: `backend-675ff9dbd8-vh4sm`; container: `backend`.
- Window (Unix nanoseconds): `1794303843064057957` through `1794303843281604134`.
- Baseline matching rules: PBL OpenMetadata Environment Discovery.
- V2 matching rules: PBL V2 Environment Inspection.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/N04.stdout), [stderr](commands/N04.stderr).

### N05: Print a path string without executing a payload

- Ground truth: `benign`; pod: `frontend-8686cd79f6-5qw4w`; container: `frontend`.
- Window (Unix nanoseconds): `1794303844305864117` through `1794303844515557668`.
- Baseline matching rules: PBL OpenMetadata Payload Execution.
- V2 matching rules: (none observed).
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/N05.stdout), [stderr](commands/N05.stderr).

### N06: Authorized maintenance script in /tmp

- Ground truth: `benign`; pod: `frontend-8686cd79f6-5qw4w`; container: `frontend`.
- Window (Unix nanoseconds): `1794303845540463215` through `1794303845753035690`.
- Baseline matching rules: (none observed).
- V2 matching rules: PBL V2 Temporary Program Execution.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/N06.stdout), [stderr](commands/N06.stderr).

### N07: Authorized maintenance reads the mounted token (discard contents)

- Ground truth: `benign`; pod: `backend-675ff9dbd8-vh4sm`; container: `backend`.
- Window (Unix nanoseconds): `1794303846777890352` through `1794303846986256934`.
- Baseline matching rules: PBL OpenMetadata ServiceAccount Token Access.
- V2 matching rules: PBL V2 Sensitive File Open.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/N07.stdout), [stderr](commands/N07.stderr).

### A01: Simulated environment and credential discovery

- Ground truth: `attack`; pod: `backend-675ff9dbd8-vh4sm`; container: `backend`.
- Window (Unix nanoseconds): `1794303848011063901` through `1794303848222955195`.
- Baseline matching rules: PBL OpenMetadata Environment Discovery.
- V2 matching rules: PBL V2 Environment Inspection, PBL V2 Sensitive File Open.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A01.stdout), [stderr](commands/A01.stderr).

### A02: Read ServiceAccount token with cat (discard contents)

- Ground truth: `attack`; pod: `backend-675ff9dbd8-vh4sm`; container: `backend`.
- Window (Unix nanoseconds): `1794303849248060114` through `1794303849458387698`.
- Baseline matching rules: PBL OpenMetadata ServiceAccount Token Access.
- V2 matching rules: PBL V2 Sensitive File Open.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A02.stdout), [stderr](commands/A02.stderr).

### A03: Read token with alternate reader head (discard contents)

- Ground truth: `attack`; pod: `backend-675ff9dbd8-vh4sm`; container: `backend`.
- Window (Unix nanoseconds): `1794303850483662886` through `1794303850701522648`.
- Baseline matching rules: (none observed).
- V2 matching rules: PBL V2 Sensitive File Open.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A03.stdout), [stderr](commands/A03.stderr).

### A04: Read process environment with alternate reader head

- Ground truth: `attack`; pod: `backend-675ff9dbd8-vh4sm`; container: `backend`.
- Window (Unix nanoseconds): `1794303851727697182` through `1794303851929516369`.
- Baseline matching rules: (none observed).
- V2 matching rules: PBL V2 Sensitive File Open.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A04.stdout), [stderr](commands/A04.stderr).

### A05: Execute original fixed-name safe payload marker

- Ground truth: `attack`; pod: `frontend-8686cd79f6-5qw4w`; container: `frontend`.
- Window (Unix nanoseconds): `1794303852954535227` through `1794303853177128399`.
- Baseline matching rules: PBL OpenMetadata Payload Execution.
- V2 matching rules: PBL V2 Temporary Program Execution.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A05.stdout), [stderr](commands/A05.stderr).

### A06: Execute a renamed safe payload marker in /tmp

- Ground truth: `attack`; pod: `frontend-8686cd79f6-5qw4w`; container: `frontend`.
- Window (Unix nanoseconds): `1794303854202982889` through `1794303854410556655`.
- Baseline matching rules: (none observed).
- V2 matching rules: PBL V2 Temporary Program Execution.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A06.stdout), [stderr](commands/A06.stderr).

### A07: Source a renamed script using shell builtins only

- Ground truth: `attack`; pod: `frontend-8686cd79f6-5qw4w`; container: `frontend`.
- Window (Unix nanoseconds): `1794303855435463755` through `1794303855644673043`.
- Baseline matching rules: (none observed).
- V2 matching rules: (none observed).
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A07.stdout), [stderr](commands/A07.stderr).

### A08: Simulated attacker inspects only environment variables

- Ground truth: `attack`; pod: `backend-675ff9dbd8-vh4sm`; container: `backend`.
- Window (Unix nanoseconds): `1794303856669798950` through `1794303856914648140`.
- Baseline matching rules: PBL OpenMetadata Environment Discovery.
- V2 matching rules: PBL V2 Environment Inspection.
- Other/default alert rules: (none observed).
- Command output: [stdout](commands/A08.stdout), [stderr](commands/A08.stderr).

## Limitations

- Syscall event-drop counters were not measured; absent alerts are observed non-matches.
- Ground truth is test-author intent, not automatically inferred maliciousness.
- Event timestamps and case windows assume the WSL client and kind kernel share a clock.
- Concurrent actions in the same target container can confound attribution; run this suite in isolation.
- Successful open-for-read proves access intent and open success, not content consumption or exfiltration.
- This suite uses safe local markers and existing lab credentials with output discarded, not a real exploit or reverse shell.
- Negative custom-rule results do not exclude alerts from default or unrelated Falco rules.
