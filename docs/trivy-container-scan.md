# Trivy Container Image Vulnerability Scan

## Objective
Scan deliberately outdated container images to generate a realistic set of
known vulnerabilities (CVEs) for the vulnerability management pipeline. These
images act as the "container" data source, complementing Prowler (cloud
misconfiguration) and Greenbone/OpenVAS (network hosts).

## Environment
- Scanner: Trivy (installed on Kali Linux VM)
- Target images: pulled from Docker Hub
- Output format: JSON (stored locally, excluded from Git via .gitignore)

## Commands
```bash
# Scan and export full results as JSON
trivy image --format json --output ~/trivy-output/python36.json python:3.6
trivy image --format json --output ~/trivy-output/nginx-old.json nginx:1.14

# Count findings by severity
jq '[.Results[].Vulnerabilities[]?.Severity] | group_by(.) | map({severity: .[0], count: length})' ~/trivy-output/python36.json
jq '[.Results[].Vulnerabilities[]?.Severity] | group_by(.) | map({severity: .[0], count: length})' ~/trivy-output/nginx-old.json
```

## Results

### python:3.6
| Severity | Count |
|----------|-------|
| CRITICAL | 321   |
| HIGH     | 3562  |
| MEDIUM   | 9899  |
| LOW      | 2691  |
| UNKNOWN  | 321   |
| **Total**| **~16795** |

### nginx:1.14 (base OS: Debian 9, end-of-life)
| Severity | Count |
|----------|-------|
| CRITICAL | 31    |
| HIGH     | 82    |
| MEDIUM   | 54    |
| LOW      | 43    |
| UNKNOWN  | 7     |
| **Total**| **~217** |

## Key observations
- The `python:3.6` image carries ~77x more vulnerabilities than `nginx:1.14`,
  driven by its much larger installed package footprint (larger attack surface).
- Trivy flagged `nginx:1.14` as running on Debian 9, which is end-of-life.
  No new security advisories are published for EOL distributions, so reported
  counts may understate real risk — absence of findings is not proof of safety.
- Takeaway: using minimal base images (slim / alpine / distroless) is one of
  the most effective container security controls.

## Notes
- Raw JSON outputs are intentionally not versioned (large files, regenerable).
  This document records the commands and summarized results as evidence.