#!/usr/bin/env python3
"""Enrich CVEs with EPSS, CISA KEV, and NIST LEV signals to build a remediation queue.

EPSS gives probability of exploitation in the next 30 days; KEV is confirmed
exploitation; LEV (NIST CSWP 41) estimates the probability a CVE has already
been exploited based on historical EPSS. Combining all three catches both the
loud, confirmed threats and the quiet ones that never make the KEV list.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

import requests

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
EPSS_BATCH_SIZE = 100  # FIRST.org caps the cve parameter at 100 ids per call


def read_cves(path: Path, cve_column: str | None) -> list[str]:
    """Pull CVE ids from a plain text file or a CSV column."""
    cves: list[str] = []
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".csv":
        reader = csv.DictReader(text.splitlines())
        if reader.fieldnames is None:
            sys.exit(f"error: {path} has no header row")
        column = cve_column or next(
            (f for f in reader.fieldnames if f.strip().lower() in ("cve", "cve_id")),
            None,
        )
        if column is None:
            sys.exit("error: no CVE column found; pass --cve-column")
        for row in reader:
            cves.extend(CVE_RE.findall(row.get(column, "") or ""))
    else:
        cves = CVE_RE.findall(text)
    # Dedupe, preserve order, normalize case
    seen: set[str] = set()
    out = []
    for cve in (c.upper() for c in cves):
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def fetch_epss(cves: list[str]) -> dict[str, dict]:
    """Fetch EPSS score and percentile for each CVE, batched."""
    scores: dict[str, dict] = {}
    for i in range(0, len(cves), EPSS_BATCH_SIZE):
        batch = cves[i : i + EPSS_BATCH_SIZE]
        resp = requests.get(
            EPSS_API, params={"cve": ",".join(batch)}, timeout=30
        )
        resp.raise_for_status()
        for item in resp.json().get("data", []):
            scores[item["cve"]] = {
                "epss": float(item["epss"]),
                "percentile": float(item["percentile"]),
            }
    return scores


def fetch_kev() -> set[str]:
    """Fetch the set of CVE ids in the CISA KEV catalog."""
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    return {v["cveID"] for v in resp.json().get("vulnerabilities", [])}


def lev_lower_bound(epss_history: list[float], window_days: int = 30) -> float:
    """LEV lower bound per NIST CSWP 41.

    LEV = 1 - product(1 - epss_i * weight) over consecutive EPSS windows.
    With only the current score available, this degrades to a single-window
    estimate; pass historical scores for a tighter bound.
    """
    p_not_exploited = 1.0
    for score in epss_history:
        p_not_exploited *= 1.0 - max(0.0, min(1.0, score))
    return 1.0 - p_not_exploited


def triage(epss: float, lev: float, in_kev: bool, epss_threshold: float) -> tuple[str, str]:
    """Assign a priority tier and a human-readable reason."""
    reasons = []
    if in_kev:
        reasons.append("KEV-listed")
    if epss >= 0.5:
        reasons.append(f"EPSS {epss:.2f}")
    if lev >= 0.5:
        reasons.append(f"LEV {lev:.2f}")
    if reasons:
        return "P1", "; ".join(reasons)
    if epss >= epss_threshold or lev >= epss_threshold:
        return "P2", f"EPSS {epss:.2f}, LEV {lev:.2f}"
    return "P3", "below thresholds"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="text file of CVE ids or scanner CSV export")
    parser.add_argument("--output", required=True, type=Path,
                        help="path for the enriched CSV queue")
    parser.add_argument("--cve-column", default=None,
                        help="CSV column containing CVE ids (auto-detected if named 'cve')")
    parser.add_argument("--epss-threshold", type=float, default=0.1,
                        help="EPSS/LEV score that promotes a CVE to P2 (default 0.1)")
    args = parser.parse_args()

    cves = read_cves(args.input, args.cve_column)
    if not cves:
        sys.exit("error: no CVE ids found in input")
    print(f"Enriching {len(cves)} CVEs...", file=sys.stderr)

    epss_scores = fetch_epss(cves)
    kev = fetch_kev()

    rows = []
    for cve in cves:
        score = epss_scores.get(cve, {"epss": 0.0, "percentile": 0.0})
        lev = lev_lower_bound([score["epss"]])
        priority, reason = triage(score["epss"], lev, cve in kev, args.epss_threshold)
        rows.append({
            "cve": cve,
            "epss": f"{score['epss']:.5f}",
            "epss_percentile": f"{score['percentile']:.3f}",
            "in_kev": cve in kev,
            "lev": f"{lev:.2f}",
            "priority": priority,
            "reason": reason,
        })

    rows.sort(key=lambda r: (r["priority"], -float(r["epss"])))
    with args.output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    counts = {p: sum(1 for r in rows if r["priority"] == p) for p in ("P1", "P2", "P3")}
    print(f"Wrote {args.output}: {counts['P1']} P1, {counts['P2']} P2, "
          f"{counts['P3']} P3", file=sys.stderr)


if __name__ == "__main__":
    main()
