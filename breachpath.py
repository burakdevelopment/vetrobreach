from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

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
        f"attempt_cost=${MODEL['infra_fixed_usd']:.0f}+{effort_hours:.1f}h*"
        f"${MODEL['labor_rate_per_hour']:.0f}/h=${attempt:.0f}; "
        f"buy_access_cap=${cap:.0f} => final=min(...)=${final:.0f}"
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



def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def combine_independent(ps: list[float]) -> float:
    x = 1.0
    for p in ps:
        p = clamp01(p)
        x *= (1.0 - p)
    return 1.0 - x



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
            scenarios.append(
                {
                    "name": "Direct data-plane exposure",
                    "scope": host,
                    "p": p,
                    "days": days,
                    "cost": cost,
                    "score": score,
                    "steps": [
                        f"Discover exposed data service(s): {', '.join(x['svc'] for x in data_items)}",
                        "Attempt unauthorized access / weak-auth window (simulated)",
                        "Outcome: potential data access or credential capture (simulated)",
                    ],
                }
            )

        
        if "WEB" in fams and "DATA" in fams:
            w = top_family("WEB", 1)
            d = top_family("DATA", 1)
            if w and d:
                base = combine_independent([w[0]["p"], d[0]["p"]])
                p = clamp01(base + 0.06)
                days = min(w[0]["days"], d[0]["days"])
                cost = min(w[0]["cost"], d[0]["cost"])
                score = p / max(1.0, days / 7.0) + 0.05
                scenarios.append(
                    {
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
                            "Outcome: potential database access/exfil path (simulated)",
                        ],
                    }
                )

        
        if "MAIL" in fams and "WEB" in fams:
            m = top_family("MAIL", 1)
            w = top_family("WEB", 1)
            if m and w:
                base = combine_independent([m[0]["p"], w[0]["p"]])
                p = clamp01(base + 0.04)
                days = min(m[0]["days"], w[0]["days"])
                cost = min(m[0]["cost"], w[0]["cost"])
                score = p / max(1.0, days / 7.0)
                scenarios.append(
                    {
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
                            "Outcome: potential account compromise leading to foothold (simulated)",
                        ],
                    }
                )

        
        if "REMOTE" in fams and "DATA" in fams:
            r = top_family("REMOTE", 1)
            d = top_family("DATA", 1)
            if r and d:
                base = combine_independent([r[0]["p"], d[0]["p"]])
                p = clamp01(base + 0.05)
                days = min(r[0]["days"], d[0]["days"])
                cost = min(r[0]["cost"], d[0]["cost"])
                score = p / max(1.0, days / 7.0)
                scenarios.append(
                    {
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
                            "Outcome: potential data access after remote foothold (simulated)",
                        ],
                    }
                )

        
        orch_items = top_family("ORCH", 2)
        if orch_items:
            p = clamp01(combine_independent([x["p"] for x in orch_items]) + 0.06)
            days = min(x["days"] for x in orch_items)
            cost = min(x["cost"] for x in orch_items)
            score = p / max(1.0, days / 7.0) + 0.08
            scenarios.append(
                {
                    "name": "Orchestration/management API exposure",
                    "scope": host,
                    "p": p,
                    "days": days,
                    "cost": cost,
                    "score": score,
                    "steps": [
                        f"Discover exposed management surface(s): {', '.join(x['svc'] for x in orch_items)}",
                        "Simulated unauthorized control attempt (misconfig/auth window)",
                        "Outcome: potential host/container control (simulated)",
                    ],
                }
            )

    return sorted(scenarios, key=lambda x: x["score"], reverse=True)[:5]



def _try_import_rich():
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

        return {
            "Console": Console,
            "Panel": Panel,
            "Table": Table,
            "Text": Text,
            "Progress": Progress,
            "SpinnerColumn": SpinnerColumn,
            "BarColumn": BarColumn,
            "TextColumn": TextColumn,
            "TimeElapsedColumn": TimeElapsedColumn,
        }
    except Exception:
        return None


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    out = {"HIGH": 0, "MED": 0, "LOW": 0}
    for f in findings:
        s = (f.get("severity") or "").upper()
        if s in out:
            out[s] += 1
    return out


def _print_rich_dashboard(report: dict[str, Any], top_n: int = 5) -> None:
    rich = _try_import_rich()
    if not rich:
        
        return

    Console = rich["Console"]
    Panel = rich["Panel"]
    Table = rich["Table"]
    Text = rich["Text"]

    console = Console()

    ascii_logo = Text(
        "\n"
        "██╗   ██╗███████╗████████╗██████╗  ██████╗ ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗\n"
        "██║   ██║██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║\n"
        "██║   ██║█████╗     ██║   ██████╔╝██║   ██║██████╔╝██████╔╝█████╗  ███████║██║     ███████║\n"
        "╚██╗ ██╔╝██╔══╝     ██║   ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║\n"
        " ╚████╔╝ ███████╗   ██║   ██║  ██║╚██████╔╝██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║\n"
        "  ╚═══╝  ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n",
        style="bold",
    )
    console.print(Panel(ascii_logo, title="VetroBreach", subtitle="Explainable attack-feasibility engine"))

    hosts = report.get("hosts", [])
    findings = report.get("findings", [])
    paths = report.get("paths", [])
    overall_p = report.get("overall_p", 0.0)

    
    total_services = sum(len(h.get("services", [])) for h in hosts)
    counts = _severity_counts(findings)

    summary_lines = [
        f"[bold]Hosts:[/bold] {len(hosts)}",
        f"[bold]Open services:[/bold] {total_services}",
        f"[bold]Findings:[/bold] {len(findings)}   "
        f"[bold red]HIGH[/bold red]={counts['HIGH']}  "
        f"[bold yellow]MED[/bold yellow]={counts['MED']}  "
        f"[bold green]LOW[/bold green]={counts['LOW']}",
        f"[bold]Scenarios:[/bold] {len(paths)}",
        f"[bold]Foothold probability (heuristic):[/bold] {overall_p:.2f}",
        f"[bold]Generated:[/bold] {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    console.print(Panel("\n".join(summary_lines), title="Scan Summary"))

    
    top = sorted(findings, key=lambda x: (x.get("severity") != "HIGH", -x.get("p", 0.0)))[:top_n]
    if top:
        t = Table(title=f"Top {min(top_n, len(top))} Findings")
        t.add_column("Severity", no_wrap=True)
        t.add_column("Host", no_wrap=True)
        t.add_column("Service", no_wrap=True)
        t.add_column("Title")
        t.add_column("p", justify="right", no_wrap=True)
        t.add_column("Cost", justify="right", no_wrap=True)

        for f in top:
            sev = (f.get("severity") or "MED").upper()
            sev_txt = sev
            if sev == "HIGH":
                sev_txt = "[bold red]HIGH[/bold red]"
            elif sev == "MED":
                sev_txt = "[bold yellow]MED[/bold yellow]"
            else:
                sev_txt = "[bold green]LOW[/bold green]"

            t.add_row(
                sev_txt,
                str(f.get("host", "-")),
                str(f.get("svc", "-")),
                str(f.get("title", "-")),
                f"{float(f.get('p', 0.0)):.2f}",
                f"${float(f.get('cost', 0.0)):.0f}",
            )
        console.print(t)



def main() -> None:
    ap = argparse.ArgumentParser(prog="vetrobreach")
    ap.add_argument("--nmap", required=True, help="Path to Nmap XML output")
    ap.add_argument("--out", default="report.md", help="Markdown output path")
    ap.add_argument(
        "--format",
        choices=["md", "json", "both"],
        default="md",
        help="Output format: md, json, or both",
    )
    ap.add_argument("--json-out", default="report.json", help="JSON output path")
    ap.add_argument("--no-cli", action="store_true", help="Disable rich CLI output (quiet mode)")
    args = ap.parse_args()

    rich = _try_import_rich()
    progress = None
    if rich and not args.no_cli:
        Progress = rich["Progress"]
        SpinnerColumn = rich["SpinnerColumn"]
        BarColumn = rich["BarColumn"]
        TextColumn = rich["TextColumn"]
        TimeElapsedColumn = rich["TimeElapsedColumn"]
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            transient=True,
        )

    
    if progress:
        with progress:
            t0 = progress.add_task("Parsing Nmap XML", total=1)
            parsed_hosts = parse_nmap_xml(args.nmap)
            progress.update(t0, advance=1)

            
            total_work = max(1, sum(len(h.services) for h in parsed_hosts))
            t1 = progress.add_task("Evaluating exposure signals", total=total_work)

            hosts_payload: list[dict] = []
            findings: list[dict] = []

            for host in parsed_hosts:
                host_services = []
                for s in host.services:
                    signal, _, _, _ = version_age_signal(s.product, s.version)
                    host_services.append(
                        {
                            "proto": s.proto,
                            "port": s.port,
                            "name": s.name,
                            "product": s.product,
                            "version": s.version,
                            "tunnel": s.tunnel,
                            "version_age": signal,
                        }
                    )

                hosts_payload.append({"ip": host.ip, "hostname": host.hostname, "services": host_services})

                for svc in host.services:
                    
                    progress.update(t1, advance=1)

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

                        findings.append(
                            {
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
                            }
                        )
    else:
        parsed_hosts = parse_nmap_xml(args.nmap)
        hosts_payload = []
        findings = []

        for host in parsed_hosts:
            host_services = []
            for s in host.services:
                signal, _, _, _ = version_age_signal(s.product, s.version)
                host_services.append(
                    {
                        "proto": s.proto,
                        "port": s.port,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                        "tunnel": s.tunnel,
                        "version_age": signal,
                    }
                )

            hosts_payload.append({"ip": host.ip, "hostname": host.hostname, "services": host_services})

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

                    findings.append(
                        {
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
                        }
                    )

    overall_p = combine_independent([f["p"] for f in findings]) if findings else 0.0
    paths = build_scenarios(findings)

    report: dict[str, Any] = {
        "hosts": hosts_payload,
        "findings": findings,
        "paths": paths,
        "overall_p": overall_p,
        "model": MODEL,
    }

    
    if not args.no_cli:
        _print_rich_dashboard(report, top_n=5)

    
    wrote_any = False

    if args.format in ("md", "both"):
        md = render_markdown(report)
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"OK (md)  -> {args.out}")
        wrote_any = True

    if args.format in ("json", "both"):
        Path(args.json_out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"OK (json)-> {args.json_out}")
        wrote_any = True

    if not wrote_any:
        
        print("No output written. Use --format md|json|both")


if __name__ == "__main__":
    main()
