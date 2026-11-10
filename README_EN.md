# Practical Cloud Security PBL Project

[한국어](README.md) | **English**

This lab creates a three-node kind Kubernetes cluster on a single Linux VM. Students generate normal and abnormal activity and inspect it with Kubernetes security observability tools.

| Category | Tool | Normal activity | Abnormal activity |
| --- | --- | --- | --- |
| Category 1 | Falco | Configuration, temporary files, health check | Shadow/token access and shell execution |
| Category 2 | Hubble | Service path and DNS traffic | Direct access, internal discovery, unusual ports |
| Category 3 | Audit Log | Pod, ConfigMap, and Service queries | Secret access, Pod exec, burst queries |

## 1. Requirements

- Ubuntu 22.04/24.04 or Debian 12
- x86_64 or ARM64
- Internet access
- A user with `sudo` privileges

Docker Engine, kind, kubectl, Helm, Cilium, Hubble, and Falco do not need to be installed in advance.

## 2. Installation

After cloning the repository, enter its directory and run:

For WSL, run these commands in a WSL2 Ubuntu terminal. Windows paths on `C:\` are accessible under `/mnt/c/` in WSL. For example, replace `path/to` in `cd /mnt/c/path/to/Practical-Cloud-Security-PBL` with the actual repository path, then continue from the `chmod` command below.

```bash
cd Practical-Cloud-Security-PBL
chmod +x install.sh category1/*.sh category2/*.sh category3/*.sh
./install.sh
```

If `./install.sh: No such file or directory` appears, use `pwd` and `ls -l install.sh` to check that the current directory contains the script.

If Docker is installed for the first time, the installer adds your user to the `docker` group and exits. Log out and reconnect, then run the installer again:

```bash
exit
ssh USER@VM_IP
cd ~/Practical-Cloud-Security-PBL
./install.sh
```

Alternatively, start a shell with the new group membership:

```bash
newgrp docker
./install.sh
```

Verify the installation:

```bash
kubectl get nodes
kubectl get pods -A
```

The environment is ready when all three nodes are `Ready` and the workload, Cilium, Hubble, and Falco Pods are `Running`. The nodes are Docker containers on the current VM, not separate VMs.

If Falco installation times out on a slow network, safely rerun the installer with a longer timeout:

```bash
WORKLOAD_WAIT_DURATION=30m ./install.sh
```

## 3. Running the Labs

Run all commands from the project root.

```bash
# Category 1: Falco
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh

# Category 2: Hubble
./category2/normal.sh
./category2/abnormal_1.sh
./category2/abnormal_2.sh
./category2/abnormal_3.sh

# Category 3: Kubernetes Audit Log
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

See the category guides for live log commands:

- [Category 1 - Falco](category1/README_EN.md)
- [Category 2 - Hubble](category2/README_EN.md)
- [Category 3 - Audit Log](category3/README_EN.md)

Each category contains `logs/normal.log` and `logs/abnormal_1.log` through `logs/abnormal_3.log`. These are representative examples; timestamps, Pod names, and IP addresses vary between runs.
