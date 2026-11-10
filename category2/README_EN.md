# Category 2: Hildegard / TeamTNT (2021)

[한국어](README.md) | **English**

## Real Incident

In the Hildegard campaign disclosed by Unit 42 in 2021, TeamTNT executed commands through anonymously accessible kubelets, scanned the internal network for kubelets and containers, and moved laterally to other workloads. Mass scanning and kubelet API abuse were central behaviors. See the [Unit 42 Hildegard analysis](https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/).

> This lab does not run masscan, malware, a miner, or command-and-control tooling. It safely simplifies the destination, port, and frequency patterns that Hubble can observe.

## Attack Mapping

| Script | Real attack phase | Safe lab behavior | Hubble evidence |
| --- | --- | --- | --- |
| `normal.sh` | Normal service traffic | Repeat frontend→backend, backend→db, DNS, health check, and retry three times | Small fixed destination set, ports 80/53, `FORWARDED` |
| `abnormal_1.sh` | Access outside the usual path | Direct frontend access to the db Service | New destination, `DROPPED` |
| `abnormal_2.sh` | Workload discovery | Rapidly probe several Services and Pod IPs | Increased destination fan-out and frequency |
| `abnormal_3.sh` | Kubelet/service probing | Probe ports 22, 443, 2379, 10250, 3306, and 6379 on multiple targets | Destination/port fan-out and repeated `DROPPED` flows |

## Run and Observe

Terminal 1:

```bash
cilium hubble port-forward
```

Terminal 2:

```bash
hubble observe --namespace pbl-security --follow --output compact
```

Terminal 3:

```bash
cd pbl-project
./category2/normal.sh
./category2/abnormal_1.sh
./category2/abnormal_2.sh
./category2/abnormal_3.sh
```

See `logs/normal.log` and `logs/abnormal_1.log` through `abnormal_3.log` for representative flows.
