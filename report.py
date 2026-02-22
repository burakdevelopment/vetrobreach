from __future__ import annotations
from typing import Any
from collections import defaultdict

def _md_table(rows: list[list[str]], headers: list[str]) -> str:
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out)

def render_markdown(report: dict[str, Any]) -> str:
    hosts = report["hosts"]
    findings = report["findings"]
    paths = report["paths"]
    overall_p = report["overall_p"]
    model = report["model"]

    lines: list[str] = []
    lines.append("# BreachPath Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- Assets scanned: **{len(hosts)}**")
    lines.append(f"- Findings (signals): **{len(findings)}**")
    lines.append(f"- Estimated probability of at least one initial foothold (heuristic): **{overall_p:.2f}**")
    lines.append("")

    lines.append("## Asset Inventory (from Nmap)")
    for h in hosts:
        lines.append(f"### {h['ip']}" + (f" ({h['hostname']})" if h.get("hostname") else ""))
        rows = []
        for s in h["services"]:
            tls = "Yes" if (s.get("tunnel") == "ssl" or s["port"] in {443, 465, 993, 995, 8443, 2376}) else "No"
            rows.append([
                f"{s['proto']}/{s['port']}",
                s["name"],
                s.get("product") or "-",
                s.get("version") or "-",
                tls,
                s.get("version_age") or "-",
            ])
        lines.append(_md_table(rows, ["Port", "Service", "Product", "Version", "TLS", "Version-Age"]))
        lines.append("")

    lines.append("## Findings (Prioritized)")
    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]].append(f)

    for sev in ["HIGH", "MED", "LOW"]:
        items = sorted(by_sev.get(sev, []), key=lambda x: x["p"], reverse=True)
        if not items:
            continue
        lines.append(f"### {sev}")
        for f in items:
            lines.append(
                f"- **{f['title']}** on `{f['host']}` via `{f['svc']}` "
                f"(p={f['p']:.2f}, time~{f['days']}d)"
            )
            if f.get("version_signal"):
                lines.append(f"  - Version signal: {f['version_signal']}")
            lines.append(f"  - Attacker cost estimate: **${f['cost']:.0f}**")
            lines.append(f"  - Cost rationale: {f['cost_rationale']}")
            # technical fix block
            for fl in f["fix"].splitlines():
                lines.append(f"  - {fl}")
        lines.append("")

    lines.append("## Most Likely Attack Paths (Service-Combination Scenarios)")
    if not paths:
        lines.append("- Not enough signals to build scenarios.")
        lines.append("")
    else:
        for i, p in enumerate(paths, 1):
            lines.append(f"### Scenario #{i} — {p['name']} (score {p['score']:.2f})")
            lines.append(f"- Scope: `{p['scope']}`")
            lines.append(f"- Estimated success probability: **{p['p']:.2f}**")
            lines.append(f"- Estimated time window: **~{p['days']} days**")
            lines.append(f"- Estimated attacker cost: **~${p['cost']:.0f}**")
            lines.append("**Steps:**")
            for step in p["steps"]:
                lines.append(f"- {step}")
            lines.append("")

    lines.append("## Fix-First Plan (Fastest Risk Reduction)")
    sev_rank = {"HIGH": 0, "MED": 1, "LOW": 2}
    fix_first = sorted(findings, key=lambda x: (sev_rank.get(x["severity"], 9), -x["p"]))[:8]
    for f in fix_first:
        lines.append(f"### {f['host']} — {f['title']}")
        lines.append(f"- Why now: severity={f['severity']}, p={f['p']:.2f}, via {f['svc']}")
        lines.append("- Immediate containment:")
        if f["family"] == "DATA":
            lines.append("  - Perimeter firewall: **DENY** public access to the DB port; allow only private/VPN.")
            lines.append("  - Bind service to private interface; enforce auth + TLS; rotate creds.")
            lines.append("  - Enable audit logging; alert on denied external connection attempts.")
        elif f["family"] == "REMOTE":
            lines.append("  - Remove from internet; require VPN/bastion; strict allowlist.")
            lines.append("  - Disable password logins (where applicable); enforce MFA/keys; rate-limit auth.")
            lines.append("  - Monitor auth failures and new successful logins from unknown sources.")
        elif f["family"] == "MAIL":
            lines.append("  - Enforce TLS-only where possible; disable plaintext ports (110/143) if not needed.")
            lines.append("  - Rate-limit auth; fail2ban; disable weak AUTH methods; keep MTA updated.")
            lines.append("  - Monitor ATO/spray patterns; lockout thresholds.")
        elif f["family"] == "ORCH":
            lines.append("  - Block management APIs from internet; require mTLS + allowlist or VPN.")
            lines.append("  - Rotate tokens/certs; enforce RBAC least privilege; enable audit logs.")
        else:
            lines.append("  - Restrict exposure (allowlist/VPN) and patch service; add monitoring/alerts.")
        lines.append("")

    lines.append("## Notes (Methodology, Cost Model, Limitations)")
    lines.append("### Methodology")
    lines.append("- This tool does **not** exploit targets. It simulates feasibility using exposure signals + heuristics.")
    lines.append("- Probability aggregation uses a simple independence assumption for initial foothold signals.")
    lines.append("- Version-age logic is heuristic: it boosts severity when product/version appears behind a known recent stable baseline.")
    lines.append("")
    lines.append("### Cost Model (why these numbers)")
    lines.append(f"- Labor rate: **${model['labor_rate_per_hour']}/hour** (used as a proxy for skilled operator time).")
    lines.append(f"- Infra fixed cost: **${model['infra_fixed_usd']}** (small VPS/proxy/tooling/subscription baseline).")
    lines.append(f"- IAB alternative cap: **${model['iab_median_usd']}** (buying access instead of spending time).")
    lines.append("- For each finding we compute:")
    lines.append("  - `attempt_cost = infra_fixed + effort_hours * labor_rate`")
    lines.append("  - `final_cost = min(attempt_cost, IAB_median)`")
    lines.append("")
    lines.append("### Limitations / How to make it enterprise-grade")
    lines.append("- Nmap alone doesn’t contain vuln facts (CVEs, misconfig proofs). Add Nessus/OpenVAS outputs for accuracy.")
    lines.append("- Lateral movement/AD/IAM requires extra context (SMB signing, LDAP/Kerberos posture, MFA coverage, logs).")
    lines.append("- Update the product baselines periodically to keep “version-age” accurate.")
    return "\n".join(lines)
