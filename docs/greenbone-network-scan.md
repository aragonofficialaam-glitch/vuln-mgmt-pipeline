# Greenbone / OpenVAS Network Vulnerability Scan

## Objective
Scan a deliberately vulnerable host over the network to generate real
host-based findings for the vulnerability management pipeline. This is the
"network" data source, complementing Prowler (cloud misconfiguration) and
Trivy (container images).

## Environment
- Scanner: Greenbone Community Edition (OpenVAS), running via Docker on Kali Linux
- Scanner host: 192.168.56.102 (Kali, host-only network)
- Target: 192.168.56.101 (Metasploitable2, host-only, no internet access)
- Scan Config: Full and fast
- Min QoD: 70
- Output format: CSV Results (stored locally, excluded from Git via .gitignore)

## Scan summary
- Scan duration: ~38 minutes
- Hosts scanned: 1
- Open ports detected: 17
- Applications detected: 19

## Findings by severity
| Severity | Count |
|----------|-------|
| Critical | 13    |
| High     | 8     |
| Medium   | 39    |
| Low      | 6     |
| Log (info)| 87   |
| False Positive | 0 |

## Notable critical findings (CVSS 10.0)
- **Distributed Ruby (dRuby/DRb) Multiple RCE** (8787/tcp) — remote code
  execution; scanner confirmed arbitrary command execution (QoD 99%).
- **Possible Backdoor: Ingreslock** (1524/tcp) — a shell backdoor listening
  on the port.
- **rexec service running** (512/tcp) and **rlogin Passwordless Login**
  (513/tcp) — legacy remote-login services, unencrypted, no password required.
- **TWiki < 4.2.4 XSS / Command Execution** (80/tcp) — outdated web app.
- **Operating System End of Life (EOL)** — host OS no longer receives patches.

## Key observations
- Remote Code Execution (RCE) and backdoors are the highest-priority findings:
  they grant direct control of the host, unlike findings that only leak
  information. Severity alone does not capture this — exploitability and impact
  must drive prioritization.
- The target runs a 2008-era Linux (kernel 2.6.24), which is why it exposes so
  many services with well-known CVEs. Large service footprint = large attack
  surface, the same principle seen with the python:3.6 container image.

## Notes
- Raw CSV output is intentionally not versioned (regenerable, may be large).
  This document records the scan configuration and summarized results as
  evidence.