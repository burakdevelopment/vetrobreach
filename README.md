# VetroBreach (vetrobreach)

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Attack Feasibility Engine** — turns **Nmap XML** into an **explainable, non-exploit** risk simulation report with **Fix-First** remediation guidance.

> ⚠️ **Safety / Ethics**
> - VetroBreach does **not** exploit targets.
> - It does **not** brute-force credentials.
> - It produces a **feasibility simulation** and **prioritization** output based on exposure signals and heuristics.
> - Use only on systems you own or have explicit permission to assess.

---

## What it’s for

Most scanners stop at “open port / service detected / CVSS”.  
VetroBreach is designed to answer **operational questions**:

- Which exposures create the most realistic **attack scenarios**?
- How likely is an **initial foothold** (heuristic)?
- What’s the **estimated attacker effort and cost**, and **why**?
- What should we fix first to reduce risk fastest (**Fix-First plan**)?

---

## Features

- **Asset Inventory** (per host): port / service / product / version / TLS / version-age signal
- **Prioritized Findings**: HIGH / MED / LOW
- **Scenario Engine (service-combination based)**:
  - Web → Data pivot chain
  - Mail + Web account takeover pressure
  - Remote access → Data impact chain
  - Direct data-plane exposure
  - Orchestration/management API exposure
- **Explainable Cost Model**:
  - Every finding includes a **cost estimate** and a **cost rationale formula**
- **Version-age Severity Boost** (heuristic):
  - If `product/version` is present in Nmap output, older versions can increase severity/probability
- **Fix-First Plan**:
  - Technical, actionable containment steps (network / config / auth / monitoring)
- **“WOW” CLI UI (Rich)**:
  - ASCII banner + panels + progress + top findings table
- **JSON export** for CI/CD or SOC pipelines

---

## Repository Layout

Minimal by design (4 Python files):

```text
vetrobreach/
  breachpath.py
  ingest_nmap.py
  kb.py
  report.py
  README.md
  requirements.txt
  LICENSE
  .gitignore
````

---

## Installation

### Requirements

* Python **3.10+**
* **Nmap** (to generate input)
* Python deps: `lxml` (+ `rich` for enhanced CLI UI)

### Install

```bash
pip install -r requirements.txt
```

---

## Usage

### 1) Generate Nmap XML

For best results, include service/version detection:

```bash
nmap -sV -oX scan.xml <TARGET>
```

Examples:

```bash
nmap -sV -oX scan.xml 10.10.10.10
nmap -sV -oX scan.xml example.com
```

> Tip: Without `-sV`, product/version might be missing → version-age logic won’t apply.

### 2) Run VetroBreach

```bash
python breachpath.py --nmap scan.xml --out report.md
```

### Output formats (MD / JSON / both)

```bash
# Markdown only (default)
python breachpath.py --nmap scan.xml --out report.md --format md

# JSON only
python breachpath.py --nmap scan.xml --format json --json-out report.json

# Both
python breachpath.py --nmap scan.xml --out report.md --format both --json-out report.json

# Disable the fancy CLI UI (useful for CI)
python breachpath.py --nmap scan.xml --format both --no-cli
```

---

## Output

VetroBreach generates:

* `report.md` (human-readable)
* `report.json` (pipeline-friendly)

The Markdown report includes:

* Executive summary
* Asset inventory tables
* Prioritized findings with remediation
* Service-combination scenarios
* Fix-First plan
* Methodology & limitations

---

## How it Works

### Input Data

VetroBreach consumes **Nmap XML**:

* Open ports / protocols
* Service names
* Product/version banners (when available)
* TLS hints via `tunnel="ssl"` and common TLS ports

### Knowledge Base Rules (KB)

In `kb.py`, each “Technique” includes:

* applicability rule (service match)
* base probability `p`
* base time window `days`
* attacker effort `effort_hours`
* severity, category, family
* technical remediation steps (“fix”)

This is **not CVE proof** — it’s a structured and explainable **risk signal model**.

### Version-Age Severity Boost (Heuristic)

If Nmap provides `product/version`, VetroBreach compares it against a small set of baseline versions for common software (e.g., OpenSSH, nginx, MariaDB, Exim).

If the reported version appears behind baseline, VetroBreach:

* bumps severity (LOW → MED → HIGH)
* increases probability slightly
* reduces time window slightly
* reduces estimated effort slightly

> This does not mean “vulnerable”.
> It means “older baseline → historically wider risk window”.

Baseline reference example:

* [OpenSSH release notes](https://www.openssh.com/releasenotes.html)

### Scenario Engine (Service Combination)

Instead of “top findings per host”, scenarios combine service families to simulate realistic chains:

* **WEB + DATA** → Web-to-Data pivot chain
* **MAIL + WEB** → Account takeover pressure
* **REMOTE + DATA** → Remote foothold → data impact
* **ORCH** → orchestration/management exposure (often high impact)
* **DATA** alone → direct data-plane exposure

Each scenario includes:

* combined probability estimate
* fastest time window estimate
* cheapest estimated attacker cost
* high-level steps (non-exploit)

---

## Explainable Attacker Cost Model

VetroBreach uses an explainable heuristic cost model to avoid magic numbers.

### 1) Attempt Cost (operator time + baseline infra)

```text
attempt_cost = infra_fixed + effort_hours * labor_rate
```

* `labor_rate` is a proxy for skilled operator time.
* `infra_fixed` covers minimal infra/tooling baseline (small VPS/proxy/subscription).

### 2) Alternative Cap: “Buy Access”

In real attacker ecosystems, “initial access” can be purchased (IAB markets).
So VetroBreach caps the estimate with a “buy access” proxy:

```text
final_cost = min(attempt_cost, IAB_median)
```

The report prints a rationale line like:

```text
attempt_cost=$60+6.0h*$80/h=$540; buy_access_cap=$1000 => final=min(...)=$540
```

**Important:** This is not a guaranteed “attacker budget”.
It’s a transparent estimate designed for prioritization and risk conversations.

---

## Why You Should NOT Trust It 100% (Limitations)

VetroBreach is a feasibility simulator, not a proof engine.

* **No vulnerability proof**
  Nmap shows exposure; it does not confirm CVEs/misconfig exploitability.
* **No network topology context**
  Segmentation, VLANs, ACLs, egress filtering, bastions can fully change pivot feasibility.
* **No identity/security telemetry**
  MFA coverage, password policies, lockouts, IdP logs heavily affect credential-risk realism.
* **Banner/version inaccuracies**
  Reverse proxies, masking, or middleboxes can misreport products/versions.
* **Independence assumption**
  Probability aggregation uses a simple independence model; real-world signals can correlate.

---

## How to Use It Responsibly

Treat VetroBreach as:

* a prioritization assistant
* a tabletop scenario generator
* an exposure-to-remediation bridge

Best practice workflow:

1. Generate report
2. Fix **DATA / ORCH / REMOTE** exposures first
3. Validate with:

   * vulnerability scanning (Nessus/OpenVAS)
   * configuration review
   * IAM posture (MFA, lockouts)
   * logs/telemetry
4. Re-run after remediation

---

## Make It Enterprise-Grade (Recommended Extensions)

To increase accuracy, ingest:

* Nessus/OpenVAS findings (CVE evidence)
* AD posture (SMB signing, LDAP, Kerberos)
* IAM/MFA coverage data
* auth telemetry (spray patterns, lockouts)
* cloud security posture (security groups, IAM policies)

---

## Disclaimer

This project is provided “as is”.
Use only on systems you own or have explicit permission to assess.

---

## Author

**Burak Akpınar**

