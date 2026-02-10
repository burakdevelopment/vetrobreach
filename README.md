# VetroBreach (vetrobreach)
**Attack Feasibility Engine** — turns **Nmap XML** output into an **explainable, non-exploit** risk simulation report with **Fix-First** remediation guidance.

> ⚠️ **Safety / Ethics**
> - VetroBreach does **not** exploit targets.
> - It does **not** brute-force credentials.
> - It produces a **feasibility simulation** and **prioritization** output based on exposure signals and heuristics.

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
- **Version-age Severity Boost**:
  - If `product/version` is present in Nmap output, older versions can increase severity/probability (heuristic)
- **Fix-First Plan**:
  - Technical, actionable containment steps (network / config / auth / monitoring)

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
```

## Installation

# Requirements

Python 3.10+
Nmap (to generate input)
lxml

* Install:
```bash
pip install -r requirements.txt
```

## Usage

# 1) Generate Nmap XML

- You want service and version detection to get the best results:

```bash
nmap -sV -oX scan.xml <TARGET>
```

# 2) Run VetroBreach

```bash
python breachpath.py --nmap scan.xml --out report.md
```

# 3) Output

- You get a Markdown report (report.md) containing:

* Executive summary
* Asset inventory tables
* Prioritized findings with remediation
* Service-combination scenarios
* Fix-First plan
* Methodology & limitations

## How it Works?

# Input Data

- VetroBreach consumes Nmap XML:

* open ports
* service names
* product/version banners
TLS indicator via tunnel="ssl" (and common TLS ports)

# Knowledge Base Rules (KB)

In kb.py, each “Technique” includes:

* applicability rule (service match)
* base probability p
* base time window days
* attacker effort effort_hours
* severity, category, family
* technical remediation steps (“fix”)

# Version-Age Severity Boost (Heuristic)

- If Nmap provides product/version, VetroBreach compares it against a small set of known baseline versions for common software (e.g., OpenSSH, nginx, MariaDB, Exim).
- If the reported version appears behind baseline, VetroBreach:

* bumps severity (LOW→MED→HIGH)
* increases probability slightly
* reduces time window slightly
* reduces estimated effort slightly

- This does not mean “vulnerable”.
- It means “older baseline → historically wider risk window”.

- Baseline example reference for OpenSSH release notes:

* OpenSSH release notes: https://www.openssh.com/releasenotes.html
* (If you fork this repo, keep baseline values updated.)

# Scenario Engine (Service Combination)

- Instead of “top findings per host”, scenarios combine service families to simulate realistic chains:

* WEB + DATA → Web-to-Data pivot chain
* MAIL + WEB → ATO pressure (credential reuse patterns)
* REMOTE + DATA → Remote foothold → data impact
* ORCH → orchestration/management exposure often has high impact
* DATA alone → direct data-plane exposure

- Each scenario includes:

* combined probability estimate
* fastest time window
* cheapest estimated attacker cost
* steps (high-level, non-exploit)

## Explainable Attacker Cost Model

* VetroBreach uses an explainable heuristic cost model to avoid magic numbers. For each finding:

# 1) Attempt Cost (operator time + baseline infra)

```text
attempt_cost = infra_fixed + effort_hours * labor_rate
```

* labor_rate is a proxy for skilled operator time.
* infra_fixed covers minimal infra/tooling baseline (small VPS/proxy/subscription).

# 2) Alternative Cap: “Buy Access”

- In real attacker ecosystems, “initial access” can be purchased (IAB markets). So we cap the cost using an approximate median access price:

```text
final_cost = min(attempt_cost, IAB_median)
```

- The report prints a cost rationale line like:


```text
attempt_cost=$60+6.0h*$80/h=$540; buy_access_cap=$1000 => final=min(...)=$540
```

- Why these parameters?

* Skilled pentesting hourly rates vary; a median ~$80/h appears as a common market proxy.
* Initial Access Broker pricing varies; many observed listings cluster under a few thousand with typical medians around ~$1,000 in reports.
* Commodity “attack infrastructure” can be inexpensive; booter/stresser economics show low monthly pricing in academic work (we abstract this into a fixed baseline).
**Important: This is not a guaranteed “attacker budget”.**
* It is a transparent estimate designed for prioritization and risk conversations.

## Why You Should NOT Trust It 100% (Limitations)

* VetroBreach is a feasibility simulator, not a proof engine.
* No vulnerability proof
* Nmap shows exposure; it does not confirm CVEs/misconfig exploitability.
* No network topology context
* Segmentation, VLANs, ACLs, egress filtering, bastions can fully change pivot feasibility.
* No identity/security telemetry
* MFA coverage, password policies, lockouts, IdP logs heavily affect credential-risk realism.
* Banner/version inaccuracies
* Reverse proxies, masking, or middleboxes can misreport products/versions.
* Independence assumption
* Probability aggregation uses a simple independence model; real-world signals can correlate.

## How to Use It Responsibly

- Treat VetroBreach as:

* a prioritization assistant
* a tabletop scenario generator
* an exposure-to-remediation bridge

- Best practice workflow:

* Generate report
* Fix DATA/ORCH/REMOTE exposures first

- Validate with:

* vulnerability scanning (Nessus/OpenVAS)
* configuration review
* IAM posture (MFA, lockouts)
* logs/telemetry
* Re-run after remediation


## Make It Enterprise-Grade (Recommended Extensions)

- To increase accuracy, ingest:

* Nessus/OpenVAS findings (CVE evidence)
* AD posture (SMB signing, LDAP, Kerberos)
* IAM/MFA coverage data
* auth telemetry (spray patterns, lockouts)
* cloud security posture (security groups, IAM policies)

## Disclaimer

* This project is provided “as is”.
* Use only on systems you own or have explicit permission to assess.

## Author 

**Burak Akpınar**
