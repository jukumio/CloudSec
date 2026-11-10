#!/usr/bin/env python3
"""Analyze controlled Category 1 cases; raw alert count is not a test count.

Only Warning-or-higher PBL custom alerts drive the primary classifications.
Default Falco alerts remain in the archive and are reported separately.
Absence means an observed non-match in a finite window, not proof of no event
loss. Detector availability and complete/stable collection gate the metrics.
"""
import argparse
import csv
import datetime as dt
import json
from pathlib import Path
import re
import sys
import tempfile

ALERT_PRIORITIES = {"emergency", "alert", "critical", "error", "warning"}


def read_json(path):
    with Path(path).open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def read_jsonl(path):
    with Path(path).open(encoding="utf-8-sig") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def timestamp_ns(value):
    """Parse RFC3339 to exact nanoseconds without truncating to microseconds."""
    match = re.fullmatch(r"(.+?)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)", value)
    if not match:
        raise ValueError(f"Invalid event time: {value!r}")
    base, fraction, zone = match.groups()
    instant = dt.datetime.fromisoformat(base + ("+00:00" if zone == "Z" else zone))
    seconds = int(instant.timestamp())
    return seconds * 1_000_000_000 + int((fraction or "").ljust(9, "0")[:9])


def parse_event(line, source):
    """Accept raw Falco JSON or kubectl --prefix JSON, ignoring prose logs."""
    start = line.find("{")
    if start < 0:
        return None
    try:
        event = json.loads(line[start:])
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict) or "rule" not in event or "output" not in event:
        return None
    fields = event.get("output_fields") or {}
    raw_time = fields.get("evt.time")
    try:
        when = int(raw_time) if raw_time is not None else timestamp_ns(event["time"])
    except (ValueError, TypeError, KeyError):
        return None
    rule = event["rule"]
    output = event["output"]
    if rule.startswith("PBL V2 ") or "PBL_V2_EVENT " in output:
        detector = "v2"
    elif rule.startswith("PBL ") and "PBL_EVENT " in output:
        detector = "baseline"
    else:
        detector = "default_or_other"
    return dict(time_ns=when, time=event.get("time"), rule=rule, output=output,
                priority=event.get("priority", ""), detector=detector,
                alert=str(event.get("priority", "")).lower() in ALERT_PRIORITIES,
                container_id=fields.get("container.id"), pod=fields.get("k8s.pod.name"),
                namespace=fields.get("k8s.ns.name"), container=fields.get("container.name"),
                command=fields.get("proc.cmdline"), file=fields.get("fd.name"),
                hostname=event.get("hostname"), source_file=source)


def matching_container(event, case, namespace):
    actual = event.get("container_id")
    expected = case.get("container_id")
    if actual and expected and actual not in ("host", "<NA>"):
        # Falco often exposes a 12-character prefix; Kubernetes exposes 64.
        return len(actual) >= 12 and (expected.startswith(actual) or actual.startswith(expected))
    return (event.get("pod") == case.get("pod")
            and event.get("namespace") == namespace
            and event.get("container") == case.get("container"))


def pod_snapshot(snapshot):
    result = {}
    for pod in snapshot.get("items", []):
        ready = any(c["type"] == "Ready" and c["status"] == "True"
                    for c in pod.get("status", {}).get("conditions", []))
        falco = [c for c in pod.get("status", {}).get("containerStatuses", []) if c["name"] == "falco"]
        result[pod["metadata"]["name"]] = dict(
            ready=ready and not pod["metadata"].get("deletionTimestamp"),
            uid=pod["metadata"].get("uid"),
            restart_count=falco[0].get("restartCount") if len(falco) == 1 else None,
            running=len(falco) == 1 and "running" in falco[0].get("state", {}))
    return result


def collection_checks(root, run):
    warnings = []
    try:
        before = pod_snapshot(read_json(root / "falco-before.json"))
        after = pod_snapshot(read_json(root / "falco-after.json"))
        stable = bool(before) and before == after and all(
            p["ready"] and p["running"] for p in before.values())
        ds = read_json(root / "daemonset-after.json")["status"]
        desired = ds.get("desiredNumberScheduled", 0)
        ready = desired > 0 and ds.get("numberReady", 0) == desired and len(after) == desired
        collected = read_jsonl(root / "log-collection.jsonl")
        logs_ok = (bool(run.get("log_collection_complete")) and bool(collected)
                   and {item["pod"] for item in collected} == set(before)
                   and all(item["exit_code"] == 0 for item in collected))
        targets = read_json(root / "targets.json")
        workloads = {pod["metadata"]["name"]: pod
                     for pod in read_json(root / "workloads-after.json").get("items", [])}
        targets_stable = bool(targets)
        for target in targets.values():
            workload = workloads.get(target["pod"], {})
            statuses = [c for c in workload.get("status", {}).get("containerStatuses", [])
                        if c["name"] == target["container"]]
            targets_stable = targets_stable and (len(statuses) == 1 and statuses[0].get("ready")
                and "running" in statuses[0].get("state", {})
                and not workload.get("metadata", {}).get("deletionTimestamp")
                and workload.get("metadata", {}).get("uid") == target.get("pod_uid")
                and statuses[0].get("restartCount", 0) == target.get("restart_count", 0)
                and statuses[0].get("containerID", "").split("://", 1)[-1] == target["container_id"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        stable = ready = logs_ok = targets_stable = False
        warnings.append(f"Collection evidence could not be verified: {exc}")
    if not stable:
        warnings.append("Falco pod identity/readiness/restart counts were not stable across the run.")
    if not ready:
        warnings.append("Not all desired Falco agents were Ready at collection end.")
    if not logs_ok:
        warnings.append("Complete log collection from every original Falco pod was not verified.")
    if not targets_stable:
        warnings.append("Target workload containers were not verified Ready with unchanged container IDs at run end.")
    warnings.append("Syscall event-drop counters were not measured; absent alerts are observed non-matches.")
    warnings.append("Ground truth is test-author intent, not automatically inferred maliciousness.")
    return dict(stable_falco_pods=stable, all_desired_agents_ready=ready,
                all_logs_collected=logs_ok, stable_workload_containers=bool(targets_stable),
                event_drop_metrics_checked=False), warnings


def configured_detectors(values):
    custom = values.get("customRules") or {}
    texts = "\n".join(str(value) for value in custom.values())
    return dict(baseline="PBL_EVENT " in texts, v2="PBL_V2_EVENT " in texts)


def classify(truth, alert):
    return ("TP" if alert else "FN") if truth == "attack" else ("FP" if alert else "TN")


def metrics(rows, detector):
    counts = {kind: sum(row[detector]["classification"] == kind for row in rows)
              for kind in ("TP", "TN", "FP", "FN")}
    tp, tn, fp, fn = (counts[k] for k in ("TP", "TN", "FP", "FN"))
    return dict(**counts, evaluated_cases=tp + tn + fp + fn,
                excluded_cases=len(rows) - tp - tn - fp - fn,
                precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None,
                false_positive_rate=fp / (fp + tn) if fp + tn else None)


def analyze(root):
    root = Path(root)
    run = read_json(root / "run.json")
    cases = read_jsonl(root / "cases.jsonl")
    checks, warnings = collection_checks(root, run)
    configured = configured_detectors(read_json(root / "active-helm-values.json"))
    events = []
    unparsed = 0
    for path in sorted((root / "logs").glob("*.log")):
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            event = parse_event(line, path.name)
            if event is None:
                unparsed += 1
            else:
                events.append(event)
    observed = {detector: any(e["detector"] == detector for e in events)
                for detector in ("baseline", "v2")}
    # A configured detector with no recorded positive control is not silently
    # scored as a detector that missed everything.
    available = {key: configured[key] and observed[key] for key in configured}
    for key in available:
        if not available[key]:
            warnings.append(f"{key}: configured={configured[key]}, events_observed={observed[key]}; metrics unavailable.")
    capture_ok = all(checks[k] for k in ("stable_falco_pods", "all_desired_agents_ready", "all_logs_collected", "stable_workload_containers"))
    rows = []
    for case in cases:
        matching = [event for event in events
                    if case["start_ns"] <= event["time_ns"] <= case["end_ns"]
                    and matching_container(event, case, run["namespace"])]
        row = dict(case)
        for detector in ("baseline", "v2"):
            own = [event for event in matching if event["detector"] == detector]
            alerts = [event for event in own if event["alert"]]
            if case["exit_code"] != 0:
                outcome = "EXECUTION_FAILED"
            elif not capture_ok:
                outcome = "COLLECTION_UNVERIFIED"
            elif not available[detector]:
                outcome = "DETECTOR_UNVERIFIED"
            else:
                outcome = classify(case["ground_truth"], bool(alerts))
            row[detector] = dict(classification=outcome, raw_events=len(own), raw_alerts=len(alerts),
                                 rules=sorted({event["rule"] for event in own}),
                                 alert_rules=sorted({event["rule"] for event in alerts}))
        other = [event for event in matching if event["detector"] == "default_or_other" and event["alert"]]
        row["default_alerts"] = dict(raw_alerts=len(other), rules=sorted({e["rule"] for e in other}))
        rows.append(row)
    summary = dict(schema_version=1, run=run, checks=checks, configured=configured, observed=observed,
                   available=available, raw_event_count=len(events), non_event_lines=unparsed,
                   warnings=warnings, metrics={key: metrics(rows, key) for key in ("baseline", "v2")},
                   cases=rows)
    (root / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with (root / "events.jsonl").open("w", encoding="utf-8") as output:
        for event in events:
            output.write(json.dumps(event, ensure_ascii=False) + "\n")
    with (root / "cases.csv").open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["case", "truth", "description", "exit_code", "baseline_expected", "baseline_observed",
                         "baseline_raw_alerts", "v2_expected", "v2_observed", "v2_raw_alerts", "default_raw_alerts"])
        for row in rows:
            writer.writerow([row["case_id"], row["ground_truth"], row["description"], row["exit_code"],
                             row["expected_baseline"], row["baseline"]["classification"], row["baseline"]["raw_alerts"],
                             row["expected_v2"], row["v2"]["classification"], row["v2"]["raw_alerts"],
                             row["default_alerts"]["raw_alerts"]])
    lines = ["# Category 1 controlled evaluation", "", "## Measurement scope", "",
             "One completed test case is one sample. Multiple agents/events do not increase the sample count.",
             "An alert means a Warning-or-higher custom rule matched within the case window and target container.",
             "Default Falco alerts are archived and listed separately; a custom-rule miss is not a claim that all Falco rules missed.",
             "Ground truth is the declared scenario intent. An authorized temporary script and an attacker script can look identical.", "",
             "## Collection checks", ""]
    lines.extend(f"- {key}: `{str(value).lower()}`" for key, value in checks.items())
    lines.extend(["", "## Observed case results", "",
                  "Expected outcomes are code-derived hypotheses; observed outcomes come only from the captured logs.", "",
                  "| Case | Ground truth | Command exit | Baseline expected / observed | V2 expected / observed | Raw custom alerts base / v2 |", 
                  "|---|---|---:|---|---|---:|"])
    for row in rows:
        lines.append(f"| {row['case_id']} | {row['ground_truth']} | {row['exit_code']} | "
                     f"{row['expected_baseline']} / {row['baseline']['classification']} | "
                     f"{row['expected_v2']} / {row['v2']['classification']} | "
                     f"{row['baseline']['raw_alerts']} / {row['v2']['raw_alerts']} |")
    lines.extend(["", "## Sample metrics", "",
                  "These rates describe only this small controlled suite, not production detection accuracy.", "",
                  "| Detector | TP | TN | FP | FN | Evaluated | Excluded | Precision | Recall | FPR |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"])
    def rate(value):
        return "not available" if value is None else f"{value:.3f}"
    for key, value in summary["metrics"].items():
        lines.append(f"| {key} | {value['TP']} | {value['TN']} | {value['FP']} | {value['FN']} | "
                     f"{value['evaluated_cases']} | {value['excluded_cases']} | {rate(value['precision'])} | "
                     f"{rate(value['recall'])} | {rate(value['false_positive_rate'])} |")
    lines.extend(["", "## Case evidence", ""])
    for row in rows:
        lines.extend([f"### {row['case_id']}: {row['description']}", "",
                      f"- Ground truth: `{row['ground_truth']}`; pod: `{row['pod']}`; container: `{row['container']}`.",
                      f"- Window (Unix nanoseconds): `{row['start_ns']}` through `{row['end_ns']}`.",
                      f"- Baseline matching rules: {', '.join(row['baseline']['rules']) or '(none observed)' }.",
                      f"- V2 matching rules: {', '.join(row['v2']['rules']) or '(none observed)' }.",
                      f"- Other/default alert rules: {', '.join(row['default_alerts']['rules']) or '(none observed)' }.",
                      f"- Command output: [stdout](commands/{row['case_id']}.stdout), [stderr](commands/{row['case_id']}.stderr).", ""])
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(["- Event timestamps and case windows assume the WSL client and kind kernel share a clock.",
                  "- Concurrent actions in the same target container can confound attribution; run this suite in isolation.",
                  "- Successful open-for-read proves access intent and open success, not content consumption or exfiltration.",
                  "- This suite uses safe local markers and existing lab credentials with output discarded, not a real exploit or reverse shell.",
                  "- Negative custom-rule results do not exclude alerts from default or unrelated Falco rules.", ""])
    (root / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true", help="Run parser/attribution/collection-gate fixtures without a cluster.")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.run_directory is None:
        parser.error("run_directory is required unless --self-test is used")
    try:
        summary = analyze(args.run_directory)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Analysis failed: {exc}\n")
    print(json.dumps({"metrics": summary["metrics"], "checks": summary["checks"]}, indent=2))
    print(f"Summary: {args.run_directory / 'summary.md'}")


def self_test():
    # A small integration fixture checks behavior rather than copying rule
    # conditions: duplicate raw alerts must count once; missing detectors,
    # failed commands, and a restarted collector must not become false misses.
    assert timestamp_ns("2026-11-10T09:24:00.123456789Z") == 1794302640123456789
    with tempfile.TemporaryDirectory(prefix="pbl-analysis-") as scratch:
        root = Path(scratch)
        (root / "logs").mkdir()
        def write(name, data):
            (root / name).write_text(json.dumps(data), encoding="utf-8")
        pod = {"metadata": {"name": "falco-test", "uid": "stable"}, "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [{"name": "falco", "restartCount": 0, "state": {"running": {}}}]}}
        write("falco-before.json", {"items": [pod]})
        write("falco-after.json", {"items": [pod]})
        write("daemonset-after.json", {"status": {"desiredNumberScheduled": 1, "numberReady": 1}})
        write("run.json", {"namespace": "pbl-security", "log_collection_complete": True})
        write("active-helm-values.json", {"customRules": {"baseline.yaml": "PBL_EVENT "}})
        write("targets.json", {"backend": {"pod": "backend-a", "container": "backend", "container_id": "a" * 64}})
        write("workloads-after.json", {"items": [{"metadata": {"name": "backend-a"}, "status": {
            "containerStatuses": [{"name": "backend", "ready": True, "state": {"running": {}},
                                   "containerID": "containerd://" + "a" * 64}]}}]})
        (root / "log-collection.jsonl").write_text(json.dumps({"pod": "falco-test", "exit_code": 0}) + "\n")
        base = dict(pod="backend-a", container="backend", container_id="a" * 64,
                    description="fixture", expected_baseline="TP", expected_v2="TP")
        cases = [dict(base, case_id="A01", ground_truth="attack", start_ns=100, end_ns=200, exit_code=0),
                 dict(base, case_id="N01", ground_truth="benign", start_ns=300, end_ns=400, exit_code=0),
                 dict(base, case_id="A02", ground_truth="attack", start_ns=500, end_ns=600, exit_code=17),
                 dict(base, case_id="N02", ground_truth="benign", start_ns=700, end_ns=800, exit_code=0),
                 dict(base, case_id="A03", ground_truth="attack", start_ns=900, end_ns=1000, exit_code=0)]
        (root / "cases.jsonl").write_text("".join(json.dumps(c) + "\n" for c in cases))
        def event(when, cid="a" * 12):
            return dict(rule="PBL Test", output="PBL_EVENT scenario=fixture", priority="Warning",
                        output_fields={"evt.time": when, "container.id": cid, "proc.cmdline": "env"}, time="unused")
        lines = ["[pod/falco-test/falco] " + json.dumps(event(150)),
                 json.dumps(event(151)), json.dumps(event(350, "b" * 12)),
                 json.dumps(event(750)), json.dumps(event(950))]
        (root / "logs/falco-test.log").write_text("\n".join(lines) + "\n")
        summary = analyze(root)
        assert summary["metrics"]["baseline"]["TP"] == 2
        assert summary["metrics"]["baseline"]["TN"] == 1
        assert summary["metrics"]["baseline"]["FP"] == 1
        assert summary["metrics"]["baseline"]["excluded_cases"] == 1
        assert summary["cases"][0]["baseline"]["raw_alerts"] == 2
        assert summary["cases"][0]["v2"]["classification"] == "DETECTOR_UNVERIFIED"
        assert summary["cases"][2]["baseline"]["classification"] == "EXECUTION_FAILED"
        assert summary["cases"][3]["baseline"]["classification"] == "FP"
        assert summary["cases"][4]["baseline"]["classification"] == "TP"
        # Identical command/target in different windows remains two separate
        # samples with independently declared authorization/attack intent.
        assert summary["cases"][3]["baseline"]["raw_alerts"] == 1
        assert summary["cases"][4]["baseline"]["raw_alerts"] == 1
        pod["status"]["containerStatuses"][0]["restartCount"] = 1
        write("falco-after.json", {"items": [pod]})
        unstable = analyze(root)
        assert unstable["cases"][0]["baseline"]["classification"] == "COLLECTION_UNVERIFIED"
        assert unstable["metrics"]["baseline"]["evaluated_cases"] == 0
    print("Analyzer self-test passed: nanosecond time, prefix parsing, container attribution, duplicate alerts, identical commands in distinct intent windows, failed cases, missing detector, and restarted collector.")


if __name__ == "__main__":
    main()
