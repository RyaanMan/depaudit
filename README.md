# depaudit

**Dependency auditor that explains vulnerabilities in plain English, using a local open-source model.**

Point it at a project folder. It reads your dependency files, checks every package against [OSV.dev](https://osv.dev) (the open vulnerability database), flags risky licenses, and uses a local [Ollama](https://ollama.com) model to explain what could go wrong. Your code never goes to a closed AI service.

## Why another audit tool?

`pip-audit` and `npm audit` list vulnerabilities. depaudit also tells you:

- **What the quick fix actually fixes.** Example: upgrading Django 2.2.0 to 2.2.28 is the minimum patch, but 14 known issues are only fixed in newer major versions. The tool says so.
- **What it means in plain English**, written by a local model.
- **Which dependencies have license conflicts** with your own project (for example a GPL package in an MIT project).

## Design rule: the model never decides facts

Small models make things up, so depaudit keeps them away from the facts:

- Vulnerabilities, severities, fix versions, and counts come from OSV.dev and are computed in plain Python.
- The model only writes the plain-English explanation. It is never shown version numbers or counts, so it cannot misstate them.

## Quick start

```bash
# 1. Install Ollama (https://ollama.com/download) and pull a small model
ollama pull qwen2.5:3b

# 2. Get the code and install the one dependency
git clone https://github.com/RyaanMan/depaudit
cd depaudit
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Run it on the included example (old packages with known problems)
python3 auditor.py examples/
```

## Usage

```bash
python3 auditor.py PATH                       # full report with AI explanation
python3 auditor.py PATH --no-ai               # facts only, no model needed
python3 auditor.py PATH --all                 # list every vulnerability
python3 auditor.py PATH --model llama3.1:8b   # use a different Ollama model
python3 auditor.py PATH --project-license Apache-2.0   # license check target
python3 auditor.py PATH --skip-licenses
```

Supported today: `requirements.txt` (pinned `==` versions) and `package.json`.

## How it works

1. Find dependency files in the folder.
2. Batch-query OSV.dev, fetch details, merge duplicates (GHSA/PYSEC aliases).
3. Compute per-package facts in code: counts by severity, minimum safe upgrade on the same major version, highest fix listed.
4. Look up each package's license on PyPI / the npm registry and flag copyleft licenses.
5. Send only vulnerability descriptions to the local model for a plain-English summary.

## Roadmap / good first issues

Contributions welcome, especially for Hacktoberfest. Good places to start:

- Support `pyproject.toml`, `Pipfile.lock`, `poetry.lock`
- Support `package-lock.json` for transitive npm dependencies
- Accept a GitHub repo URL and scan it directly
- JSON and Markdown output formats
- Unit tests for version comparison and fix-version logic
- More ecosystems: Go (`go.mod`), Rust (`Cargo.lock`)
- A small Streamlit web UI

## Limitations

- Only pinned versions are checked (unpinned `package>=1.0` lines are skipped).
- Transitive dependencies are not scanned yet.
- License detection depends on what the package registry reports; unknown licenses are flagged for manual review.
- Small local models can be generic. Treat the AI text as a readable summary and the tables as the source of truth.

## License

MIT. See [LICENSE](LICENSE).
