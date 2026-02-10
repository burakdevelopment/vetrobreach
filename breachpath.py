from __future__ import annotations
import argparse
import re
from ingest_nmap import parse_nmap_xml
from kb import KB
from report import render_markdown


MODEL = {
    
    "labor_rate_per_hour": 80.0,
    
    "infra_fixed_usd": 60.0,
    
    "iab_median_usd": 1000.0,
}

def estimate_cost(effort_hours: float) -> tuple[float, str]:
    attempt = MODEL["infra_fixed_usd"] + effort_hours * MODEL["labor_rate_per_hour"]
    cap = MODEL["iab_median_usd"]
    final = min(attempt, cap)
    rationale = (
        f"attempt_cost=${MODEL['infra_fixed_usd']:.0f}+{effort_hours:.1f}h*${MODEL['labor_rate_per_hour']:.0f}/h"
        f"=${attempt:.0f}; buy_access_cap=${cap:.0f} => final=min(...)=${final:.0f}"
    )
    return final, rationale


def _norm(s: str | None) -> str:
    return (s or "").strip()

def _parse_ver_nums(v: str) -> tuple[int, ...] | None:

    if not v:
        return None
    m = re.findall(r"\d+", v)
    if not m:
        return None
    return tuple(int(x) for x in m[:4])

def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    return (aa > bb) - (aa < bb)

def bump_severity(sev: str) -> str:
    return {"LOW": "MED", "MED": "HIGH", "HIGH": "HIGH"}.get(sev, sev)

PRODUCT_BASELINES = [
    (["openssh"], "10.2", "OpenSSH"),
    (["nginx"], "1.28.2", "nginx"),
    (["mariadb"], "10.6.25", "MariaDB 10.6 LTS line"),
    (["exim"], "4.99.1", "Exim"),
]

def version_age_signal(product: str | None, version: str | None) -> tuple[str | None, float, int, float]:

    p = _norm(product).lower()
    v = _norm(version)
    vt = _parse_ver_nums(v)
    if not p or not v or vt is None:
        return None, 0.0, 0, 0.0

    for keys, latest, label in PRODUCT_BASELINES:
        if any(k in p for k in keys):
            lt = _parse_ver_nums(latest)
            if lt is None:
                continue
            cmpv = _cmp(vt, lt)
            if cmpv >= 0:
                return f"{label}: reported {v} (baseline {latest}) → up-to-date/unknown", 0.0, 0, 0.0

            behind = "behind baseline"
            p_boost = 0.05
            days_delta = -2
            effort_delta = -1.0
            if len(vt) >= 2 and len(lt) >= 2 and vt[0] <= lt[0] - 1:
                behind = "significantly behind baseline"
                p_boost = 0.08
                days_delta = -4
                effort_delta = -2.0

            return f"{label}: reported {v} vs baseline {latest} → {behind}", p_boost, days_delta, effort_delta

    return None, 0.0, 0, 0.0

def combine_independent(ps: list[float]) -> float:
    x = 1.0
    for p in ps:
        p = max(0.0, min(1.0, p))
        x *= (1.0 - p)
    return 1.0 - x

def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))

def build_scenarios(findings: list[dict]) -> list[dict]:
    by_host: dict[str, list[dict]] = {}
    for f in findings:
        by_host.setdefault(f["host"], []).append(f)

    scenarios: list[dict] = []

    for host, items in by_host.items():
        fams = {f["family"] for f in items}
        
        def top_family(fam: str, n: int = 2) -> list[dict]:
            return sorted([x for x in items if x["family"] == fam], key=lambda x: x["p"], reverse=True)[:n]

        
        data_items = top_family("DATA", 2)
        if data_items:
            ps = [x["p"] for x in data_items]
            p = combine_independent(ps)
            days = min(x["days"] for x in data_items)
            cost = min(x["cost"] for x in data_items)
            score = p / max(1.0, days / 7.0)
            scenarios.append({
                "name": "Direct data-plane exposure",
                "scope": host,
                "p": p,
                "days": days,
                "cost": cost,
                "score": score,
                "steps": [
                    f"Discover exposed data service(s): {', '.join(x['svc'] for x in data_items)}",
                    "Attempt unauthorized access / weak-auth window (simulated)",
                    "Outcome: potential data access or credential capture (simulated)"
                ]
            })

        
        if "WEB" in fams and "DATA" in fams:
            w = top_family("WEB", 1)
            d = top_family("DATA", 1)
            if w and d:
                base = combine_independent([w[0]["p"], d[0]["p"]])
                
                p = clamp01(base + 0.06)
                days = min(w[0]["days"], d[0]["days"])  # fastest window
                cost = min(w[0]["cost"], d[0]["cost"])
                score = p / max(1.0, days / 7.0) + 0.05
                scenarios.append({
                    "name": "Web-to-Data pivot chain",
                    "scope": host,
                    "p": p,
                    "days": days,
                    "cost": cost,
                    "score": score,
                    "steps": [
                        f"Initial foothold pressure on web surface: {w[0]['svc']}",
                        "Simulated foothold (auth/misconfig/vuln window)",
                        f"Pivot attempt toward data-plane: {d[0]['svc']}",
                        "Outcome: potential database access/exfil path (simulated)"
                    ]
                })

        
        if "MAIL" in fams and "WEB" in fams:
            m = top_family("MAIL", 1)
            w = top_family("WEB", 1)
            if m and w:
                base = combine_independent([m[0]["p"], w[0]["p"]])
                p = clamp01(base + 0.04)
                days = min(m[0]["days"], w[0]["days"])
                cost = min(m[0]["cost"], w[0]["cost"])
                score = p / max(1.0, days / 7.0)
                scenarios.append({
                    "name": "Account takeover pressure (Mail + Web)",
                    "scope": host,
                    "p": p,
                    "days": days,
                    "cost": cost,
                    "score": score,
                    "steps": [
                        f"Credential surface exposure: {m[0]['svc']}",
                        "Simulated credential attack window (spray/stuffing patterns)",
                        f"Attempt login reuse on web surface: {w[0]['svc']}",
                        "Outcome: potential account compromise leading to foothold (simulated)"
                    ]
                })

        
        if "REMOTE" in fams and "DATA" in fams:
            r = top_family("REMOTE", 1)
            d = top_family("DATA", 1)
            if r and d:
                base = combine_independent([r[0]["p"], d[0]["p"]])
                p = clamp01(base + 0.05)
                days = min(r[0]["days"], d[0]["days"])
                cost = min(r[0]["cost"], d[0]["cost"])
                score = p / max(1.0, days / 7.0)
                scenarios.append({
                    "name": "Remote access to data impact chain",
                    "scope": host,
                    "p": p,
                    "days": days,
                    "cost": cost,
                    "score": score,
                    "steps": [
                        f"Remote access surface: {r[0]['svc']}",
                        "Simulated initial access (auth window)",
                        f"Data-plane exposure: {d[0]['svc']}",
                        "Outcome: potential data access after remote foothold (simulated)"
                    ]
                })

        
        orch_items = top_family("ORCH", 2)
        if orch_items:
            p = clamp01(combine_independent([x["p"] for x in orch_items]) + 0.06)
            days = min(x["days"] for x in orch_items)
            cost = min(x["cost"] for x in orch_items)
            score = p / max(1.0, days / 7.0) + 0.08
            scenarios.append({
                "name": "Orchestration/management API exposure",
                "scope": host,
                "p": p,
                "days": days,
                "cost": cost,
                "score": score,
                "steps": [
                    f"Discover exposed management surface(s): {', '.join(x['svc'] for x in orch_items)}",
                    "Simulated unauthorized control attempt (misconfig/auth window)",
                    "Outcome: potential host/container control (simulated)"
                ]
            })

    
    return sorted(scenarios, key=lambda x: x["score"], reverse=True)[:5]


def main():
    ap = argparse.ArgumentParser(prog="breachpath")
    ap.add_argument("--nmap", required=True, help="Path to nmap XML output")
    ap.add_argument("--out", default="breachpath_report.md", help="Output report path (md)")
    args = ap.parse_args()

    parsed_hosts = parse_nmap_xml(args.nmap)

    hosts_payload: list[dict] = []
    findings: list[dict] = []

    
    for host in parsed_hosts:
        host_services = []
        for s in host.services:
            signal, _, _, _ = version_age_signal(s.product, s.version)
            host_services.append({
                "proto": s.proto,
                "port": s.port,
                "name": s.name,
                "product": s.product,
                "version": s.version,
                "tunnel": s.tunnel,
                "version_age": signal,
            })

        hosts_payload.append({
            "ip": host.ip,
            "hostname": host.hostname,
            "services": host_services
        })

        for svc in host.services:
            for tech in KB:
                if not tech.applies(host, svc):
                    continue

                
                p = tech.base_p
                days = tech.base_days
                effort = tech.effort_hours
                sev = tech.severity

                
                signal, p_boost, days_delta, effort_delta = version_age_signal(svc.product, svc.version)
                if signal and p_boost > 0:
                    sev = bump_severity(sev)
                    p = clamp01(p + p_boost)
                    days = max(1, days + days_delta)
                    effort = max(1.0, effort + effort_delta)

                cost, rationale = estimate_cost(effort)

                findings.append({
                    "host": host.ip,
                    "svc": f"{svc.proto}/{svc.port}:{svc.name}",
                    "title": tech.title,
                    "severity": sev,
                    "category": tech.category,
                    "family": tech.family,
                    "p": p,
                    "days": days,
                    "cost": cost,
                    "cost_rationale": rationale,
                    "fix": tech.fix,
                    "version_signal": signal,
                })

    overall_p = combine_independent([f["p"] for f in findings]) if findings else 0.0
    paths = build_scenarios(findings)

    report = {
        "hosts": hosts_payload,
        "findings": findings,
        "paths": paths,
        "overall_p": overall_p,
        "model": MODEL,
    }

    md = render_markdown(report)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"OK -> {args.out}")

if __name__ == "__main__":
    main()
