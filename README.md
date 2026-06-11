# Vulnerability Prioritization Toolkit

Enrich CVE lists with **EPSS**, **CISA KEV**, and **NIST LEV** scores to produce a data-driven remediation queue — because 95% of vulnerabilities are never exploited, and treating them all the same wastes your team's time.

## Why

CVSS alone is a poor prioritization signal. This toolkit combines three exploitation-likelihood signals:

| Signal | Source | What it tells you |
|---|---|---|
| **EPSS** | [FIRST.org](https://www.first.org/epss/) | Probability of exploitation in the next 30 days |
| **KEV** | [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploitation in the wild |
| **LEV** | [NIST CSWP 41](https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities/final) | Probability the CVE has *already* been exploited (catches what KEV misses) |

The output is a ranked remediation queue you can hand to your patching team.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Enrich a list of CVEs (one per line, or CSV with a 'cve' column)
python prioritize.py --input cves.txt --output queue.csv

# Pipe from a scanner export
python prioritize.py --input tenable_export.csv --cve-column "CVE" --output queue.csv

# Set custom thresholds
python prioritize.py --input cves.txt --epss-threshold 0.1 --output queue.csv
```

## Scoring model

Each CVE gets a composite priority tier:

1. **P1 — Patch now**: In KEV, or LEV ≥ 0.5, or EPSS ≥ 0.5
2. **P2 — Patch this cycle**: EPSS ≥ 0.1 or LEV ≥ 0.1
3. **P3 — Standard cadence**: everything else

Tune thresholds to your environment's risk appetite via CLI flags.

## Example output

```
cve,epss,epss_percentile,in_kev,lev,priority,reason
CVE-2025-5419,0.94321,0.999,True,0.87,P1,KEV-listed; EPSS 0.94
CVE-2024-21412,0.62110,0.981,True,0.71,P1,KEV-listed; EPSS 0.62
CVE-2023-44487,0.08540,0.912,False,0.22,P2,LEV 0.22
...
```

## Data sources

- EPSS scores: `https://api.first.org/data/v1/epss` (no API key required)
- KEV catalog: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- LEV: computed from historical EPSS data per NIST CSWP 41 methodology

## License

MIT
