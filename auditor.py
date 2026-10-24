#!/usr/bin/env python3
"""depaudit: scan dependency files, check OSV.dev, explain with a local Ollama model.

The model never decides versions or severities. Python computes all facts from OSV
data; the model only writes the plain-English explanation around them.

Usage:
    python3 auditor.py path/to/repo
    python3 auditor.py path/to/repo --model qwen2.5:3b
    python3 auditor.py path/to/repo --no-ai
    python3 auditor.py path/to/repo --all      # print every vulnerability
"""
import argparse
import json
import re
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
import requests  # noqa: E402

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
OLLAMA_URL = "http://localhost:11434/api/generate"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ---------- 1. parse dependency files ----------
def parse_requirements(path):
    deps = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-]+)", line)
        if m:
            deps.append(("PyPI", m.group(1), m.group(2)))
    return deps


def parse_package_json(path):
    data = json.loads(path.read_text())
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            m = re.search(r"\d+\.\d+\.\d+[\w.\-+]*", ver)
            if m:
                deps.append(("npm", name, m.group(0)))
    return deps


def find_deps(root):
    root = Path(root)
    deps = []
    for p in root.rglob("requirements*.txt"):
        if "node_modules" not in p.parts and "venv" not in p.parts:
            deps += parse_requirements(p)
    for p in root.rglob("package.json"):
        if "node_modules" not in p.parts:
            deps += parse_package_json(p)
    return sorted(set(deps))


# ---------- 2. query OSV ----------
def query_osv(deps):
    found = {}
    for i in range(0, len(deps), 500):
        chunk = deps[i:i + 500]
        body = {"queries": [
            {"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk
        ]}
        r = requests.post(OSV_BATCH, json=body, timeout=30)
        r.raise_for_status()
        for dep, res in zip(chunk, r.json()["results"]):
            ids = [v["id"] for v in res.get("vulns", [])]
            if ids:
                found[dep] = ids
    return found


def vuln_details(vuln_id, pkg_name):
    r = requests.get(OSV_VULN.format(vuln_id), timeout=30)
    r.raise_for_status()
    v = r.json()
    severity = (v.get("database_specific", {}).get("severity") or "UNKNOWN").upper()
    fixed = set()
    for aff in v.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != pkg_name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.add(ev["fixed"])
    return {
        "id": vuln_id,
        "aliases": v.get("aliases", []),
        "severity": severity,
        "summary": v.get("summary") or "(no summary)",
        "fixed_in": sorted(fixed),
    }


def collect(found):
    findings = []
    for (eco, name, ver), ids in found.items():
        for vid in ids:
            try:
                d = vuln_details(vid, name)
            except requests.RequestException:
                continue
            d.update(package=name, version=ver, ecosystem=eco)
            findings.append(d)
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 4))
    return dedupe(findings)


def dedupe(findings):
    """GHSA and PYSEC often describe the same CVE. Keep the first (best severity)."""
    seen, out = set(), []
    for f in findings:
        ids = {f["id"], *f["aliases"]}
        key = (f["package"], f["version"])
        if any((key, i) in seen for i in ids):
            continue
        for i in ids:
            seen.add((key, i))
        out.append(f)
    return out


# ---------- 2b. license check ----------
def get_license(eco, name, ver):
    try:
        if eco == "PyPI":
            r = requests.get(f"https://pypi.org/pypi/{name}/{ver}/json", timeout=15)
            r.raise_for_status()
            info = r.json()["info"]
            cls = [c.split("::")[-1].strip() for c in info.get("classifiers", [])
                   if c.startswith("License ::")]
            lic = (info.get("license_expression") or info.get("license") or "").strip()
            if len(lic) > 80:  # some packages paste the whole license text here
                lic = ""
            return "; ".join(x for x in [lic] + cls if x) or "UNKNOWN"
        if eco == "npm":
            safe = name.replace("/", "%2F")
            r = requests.get(f"https://registry.npmjs.org/{safe}/{ver}", timeout=15)
            r.raise_for_status()
            lic = r.json().get("license")
            if isinstance(lic, dict):
                lic = lic.get("type")
            return lic or "UNKNOWN"
    except (requests.RequestException, ValueError, KeyError):
        pass
    return "UNKNOWN"


def license_kind(lic):
    u = lic.upper()
    if "LGPL" in u or "LESSER GENERAL" in u or "MPL" in u or "MOZILLA" in u:
        return "weak copyleft"
    if re.search(r"\bA?GPL|GNU GENERAL|AFFERO", u):
        return "strong copyleft"
    return None


def check_licenses(deps, project_license):
    """Return list of (package, version, license, level, message)."""
    project_is_copyleft = "GPL" in project_license.upper()
    out = []
    for eco, name, ver in deps:
        lic = get_license(eco, name, ver)
        kind = license_kind(lic)
        if lic == "UNKNOWN":
            out.append((name, ver, lic, "REVIEW", "license could not be determined"))
        elif kind == "strong copyleft" and not project_is_copyleft:
            out.append((name, ver, lic, "CONFLICT",
                        f"{kind}; may force your {project_license} project to be released "
                        "under the same terms"))
        elif kind == "weak copyleft":
            out.append((name, ver, lic, "REVIEW", f"{kind}; fine if used as a library, "
                        "check before modifying it"))
    return out


# ---------- 3. compute facts in code (not in the model) ----------
def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def is_version(v):
    return re.fullmatch(r"\d+(\.\d+)*", v) is not None


def summarize(findings):
    pk = {}
    for f in findings:
        s = pk.setdefault((f["package"], f["version"]), {
            "package": f["package"], "installed": f["version"], "total_vulns": 0,
            "severity_counts": {}, "upgrade_same_major": None,
            "vulns_needing_major_upgrade": 0, "highest_fix_listed": None,
        })
        s["total_vulns"] += 1
        s["severity_counts"][f["severity"]] = s["severity_counts"].get(f["severity"], 0) + 1
        fixes = [x for x in f["fixed_in"] if is_version(x)]
        inst = vkey(f["version"])
        same = [x for x in fixes if vkey(x)[:1] == inst[:1] and vkey(x) > inst]
        if same:
            m = min(same, key=vkey)
            cur = s["upgrade_same_major"]
            if cur is None or vkey(m) > vkey(cur):
                s["upgrade_same_major"] = m
        else:
            s["vulns_needing_major_upgrade"] += 1
        if fixes:
            h = max(fixes, key=vkey)
            cur = s["highest_fix_listed"]
            if cur is None or vkey(h) > vkey(cur):
                s["highest_fix_listed"] = h
    return sorted(
        pk.values(),
        key=lambda s: (-s["severity_counts"].get("CRITICAL", 0), -s["total_vulns"]),
    )


# ---------- 4. explain with a local model ----------
def explain(findings, summary, model):
    top = {}
    for f in findings:  # already sorted by severity
        top.setdefault(f["package"], [])
        if len(top[f["package"]]) < 3:
            top[f["package"]].append(
                {"id": f["id"], "severity": f["severity"], "summary": f["summary"]}
            )
    slim = []
    for s in summary:
        slim.append({
            "package": s["package"],
            "worst_severity": min(s["severity_counts"], key=lambda k: SEV_ORDER.get(k, 4)),
            "example_issues": [t["summary"] for t in top.get(s["package"], [])],
        })
    facts = json.dumps(slim, indent=1)
    prompt = (
        "You are a security assistant. The JSON below is computed from confirmed "
        "vulnerability data. Use ONLY this data.\n\n"
        "Rules: write NO numbers and NO version numbers anywhere. Never invent CVEs. "
        "Do not recommend upgrade versions; another tool prints those.\n\n"
        "Write a short plain-English report:\n"
        "1. Overall risk in 2 sentences.\n"
        "2. For each package, in the order given: 2 sentences on what an attacker could "
        "do, based on example_issues.\n\n"
        f"DATA:\n{facts}"
    )
    r = requests.post(
        OLLAMA_URL, json={"model": model, "prompt": prompt, "stream": False}, timeout=300
    )
    r.raise_for_status()
    return r.json()["response"]


# ---------- 5. CLI ----------
def report_licenses(deps, args):
    if args.skip_licenses:
        return
    print(f"\nLICENSE CHECK (your project license: {args.project_license})")
    issues = check_licenses(deps, args.project_license)
    if not issues:
        print("No license conflicts found.")
        return
    for name, ver, lic, level, msg in issues:
        print(f"[{level:<8}] {name} {ver}: {lic} - {msg}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="repo or folder to scan")
    ap.add_argument("--model", default="qwen2.5:3b")
    ap.add_argument("--no-ai", action="store_true", help="skip the model")
    ap.add_argument("--all", action="store_true", help="print every vulnerability")
    ap.add_argument("--project-license", default="MIT",
                    help="license of YOUR project, used for the license check (default MIT)")
    ap.add_argument("--skip-licenses", action="store_true", help="skip the license check")
    args = ap.parse_args()

    deps = find_deps(args.path)
    if not deps:
        sys.exit("No pinned dependencies found (need requirements.txt with == or package.json).")
    print(f"Scanning {len(deps)} dependencies via OSV.dev...\n")

    findings = collect(query_osv(deps))
    if not findings:
        print("No known vulnerabilities found.")
        report_licenses(deps, args)
        return

    summary = summarize(findings)
    print(f"{len(findings)} unique vulnerabilities (duplicates merged)\n")
    print("PER PACKAGE")
    for s in summary:
        sev = ", ".join(f"{n} {k.lower()}" for k, n in sorted(
            s["severity_counts"].items(), key=lambda kv: SEV_ORDER.get(kv[0], 4)))
        up = s["upgrade_same_major"] or "no same-major fix"
        print(f"- {s['package']} {s['installed']}: {s['total_vulns']} vulns ({sev})")
        print(f"    upgrade to at least {up} (same major); highest fix listed: "
              f"{s['highest_fix_listed']}; needing major upgrade: "
              f"{s['vulns_needing_major_upgrade']}")

    shown = findings if args.all else findings[:10]
    print(f"\n{'ALL' if args.all else 'TOP 10'} VULNERABILITIES")
    for f in shown:
        fix = ", ".join(x for x in f["fixed_in"] if is_version(x)) or "no fix listed"
        print(f"[{f['severity']:<8}] {f['package']} {f['version']}  {f['id']}  (fix: {fix})")
        print(f"           {f['summary']}")
    if not args.all and len(findings) > 10:
        print(f"\n...and {len(findings) - 10} more (use --all to see them)")

    report_licenses(deps, args)

    if not args.no_ai:
        print("\n" + "=" * 60 + f"\nAI REPORT (local model: {args.model})\n" + "=" * 60)
        try:
            print(explain(findings, summary, args.model))
        except requests.RequestException as e:
            print(f"Could not reach Ollama ({e}). Is the Ollama app running?")


if __name__ == "__main__":
    main()
