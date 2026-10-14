# Recon Automation Script — Kali Linux Edition

A Python-based reconnaissance automation tool that runs **dirsearch**, **nuclei**, and **nikto** against a target URL — one after another — and produces a clean PDF report with all findings.

Built and tested for **Kali Linux**.

---

## Table of Contents

1. [What This Tool Does](#1-what-this-tool-does)
2. [Features](#2-features)
3. [Project Structure](#3-project-structure)
4. [Prerequisites](#4-prerequisites)
5. [Installation — Step by Step](#5-installation--step-by-step)
6. [Running the Script](#6-running-the-script)
7. [Output Structure](#7-output-structure)
8. [PDF Report Contents](#8-pdf-report-contents)
9. [Tool Commands Reference](#9-tool-commands-reference)
10. [Troubleshooting](#10-troubleshooting)
11. [Notes & Warnings](#11-notes--warnings)

---

## 1. What This Tool Does

1. Prompts you **once** for a target URL
2. Creates a folder named after that URL
3. Runs three recon tools **sequentially** (one after another, never parallel):
   - **Dirsearch** — directory/file brute-forcing
   - **Nuclei** — template-based vulnerability scanning (all severities)
   - **Nikto** — web server vulnerability scanning (full test suite)
4. Streams each tool's live output to the terminal **and** to a raw text file
5. On any error in any tool, logs the error and **continues to the next tool** — it never aborts mid-run
6. When all three finish, builds a **PDF report** containing parsed findings + raw output for each tool

---

## 2. Features

- ✅ One-time URL prompt — no repeated input
- ✅ Strictly sequential execution: dirsearch → nuclei → nikto
- ✅ Live progress banners showing `[1/3] RUNNING DIRSEARCH ...`
- ✅ Error-tolerant: missing binaries, non-zero exit codes, and timeouts are all logged and skipped
- ✅ ANSI color codes stripped → clean PDF, no `^[[92m` garbage
- ✅ Folder named after the target URL (auto-deduplicated with `_1`, `_2`, ...)
- ✅ PDF includes **parsed findings** (tables / colored bullets) **and** full raw output
- ✅ Nuclei runs with **no severity filter** — critical, high, medium, low, info, unknown all included
- ✅ Nikto runs with its **full test suite** (no `-Tuning` restriction) and auto-adds `-ssl` for HTTPS
- ✅ Pre-flight PATH check for each tool before running

---

## 3. Project Structure

```
recon-tool/
├── recon_kali.py          # The main script
├── requirements.txt       # Python dependencies
├── README.md              # This file
└── venv/                  # Python virtual environment (created during setup)
```

After a scan, a per-target folder is created in the same directory:

```
recon-tool/
└── example.com/
    ├── dirsearch_raw.txt
    ├── nuclei_raw.txt
    ├── nikto_raw.txt
    └── recon_report_example.com.pdf
```

---

## 4. Prerequisites

### Operating System
- **Kali Linux** (2023.x or newer recommended)
- Any Debian-based distro with the required tools should also work

### System Tools (must be installed and on PATH)

| Tool | Purpose | Install on Kali |
|------|---------|-----------------|
| `dirsearch` | Directory brute-forcing | `sudo apt install -y dirsearch` *(or `pipx install dirsearch`)* |
| `nuclei` | Template-based vulnerability scanning | `sudo apt install -y nuclei` |
| `nikto` | Web server scanner | `sudo apt install -y nikto` *(usually pre-installed)* |

### Python
- Python **3.8+**
- `python3-venv` package
- `python3-pip`

### Python Packages (installed inside venv)
- `reportlab` (for PDF generation)

---

## 5. Installation — Step by Step

> ⚠️ **IMPORTANT — READ THIS FIRST**
>
> Modern Kali Linux blocks system-wide `pip install` due to PEP 668 ("externally-managed-environment"). **You MUST create and activate a Python virtual environment (venv)** before installing any Python packages or running the script.
>
> If you skip this step, `pip install reportlab` will fail with:
> ```
> error: externally-managed-environment
> × This environment is externally managed
> ```

### Step 1 — Update Kali and install system tools

```bash
sudo apt update
sudo apt install -y dirsearch nuclei nikto python3-venv python3-pip
```

### Step 2 — Update nuclei templates (required)

Nuclei ships with an empty template database. Without this step, nuclei finds nothing.

```bash
nuclei -update-templates
```

Verify:

```bash
nuclei -templates-version
```

### Step 3 — Create the project folder

```bash
mkdir -p ~/recon-tool
cd ~/recon-tool
```

Place `recon_kali.py` and `requirements.txt` into this folder.

### Step 4 — Create the Python virtual environment

```bash
python3 -m venv venv
```

This creates a `venv/` folder containing an isolated Python environment.

### Step 5 — Activate the virtual environment

**You must do this every time you open a new terminal before running the script.**

```bash
source venv/bin/activate
```

When active, your prompt changes to include `(venv)`:

```
(venv) kali@kali:~/recon-tool$
```

### Step 6 — Install Python dependencies inside the venv

With the venv **activated**, run:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install reportlab
```

### Step 7 — Verify the setup

```bash
which dirsearch nuclei nikto
python -c "import reportlab; print('reportlab OK')"
```

Expected:
- `which` prints a path for each of the three tools
- Python prints `reportlab OK`

If any line is blank, jump to [Troubleshooting](#10-troubleshooting).

### Step 8 — Create `requirements.txt` (if not already present)

```txt
reportlab>=4.0.0
```

That's the only Python package needed. `dirsearch`, `nuclei`, and `nikto` are system tools, not pip packages.

---

## 6. Running the Script

### Every session, run these commands in order:

```bash
cd ~/recon-tool
source venv/bin/activate
python3 recon_kali.py
```

### The script will prompt:

```
==============================================================
  Recon Automation — Kali Linux Edition
  dirsearch -> nuclei -> nikto   (sequential, error-tolerant)
==============================================================
Enter target URL (e.g. https://example.com):
```

Type the target (`https://example.com` or `example.com`) and press **Enter**.

### What you will see during the scan

```
==============================================================
  [1/3]  RUNNING  DIRSEARCH  ...
==============================================================
[*] Command : dirsearch -u https://example.com -r --random-agent ...
[*] Output  : /home/kali/recon-tool/example.com/dirsearch_raw.txt
--------------------------------------------------------------
<live dirsearch output>
[+] Dirsearch completed successfully (exit 0).

==============================================================
  [2/3]  RUNNING  NUCLEI  ...
==============================================================
<live nuclei output>
[+] Nuclei completed successfully (exit 0).

==============================================================
  [3/3]  RUNNING  NIKTO  ...
==============================================================
<live nikto output>
[+] Nikto completed successfully (exit 0).

[*] Building PDF report -> /home/kali/recon-tool/example.com/recon_report_example.com.pdf

==============================================================
[+] Done.
[+] Report : /home/kali/recon-tool/example.com/recon_report_example.com.pdf
[+] Raw outputs in: /home/kali/recon-tool/example.com
==============================================================
```

### When done — deactivate the venv

```bash
deactivate
```

---

## 7. Output Structure

```
example.com/
├── dirsearch_raw.txt              # Raw dirsearch output
├── nuclei_raw.txt                 # Raw nuclei findings
├── nikto_raw.txt                  # Raw nikto output
└── recon_report_example.com.pdf   # Final PDF report
```

**Folder naming rules:**

- Folder name is derived from the URL (`https://` and `http://` stripped)
- Non-alphanumeric characters replaced with `_`
- If the folder already exists, `_1`, `_2`, ... is appended so nothing is overwritten

---

## 8. PDF Report Contents

### Page 1 — Cover & Summary
- Target URL
- Results folder path
- Scan start / finish timestamps
- List of tools run
- **Summary table** — one row per tool: Status (OK / FAILED), Findings count, Raw output size
- **Nuclei severity breakdown** — counts per severity
- **Errors encountered** block (only shown if any tool failed)

### Per-Tool Sections
For each tool (`Dirsearch Results`, `Nuclei Results`, `Nikto Results`):

1. **Command line** that was executed
2. **Findings** — parsed, human-readable results:
   - **Dirsearch** → table with columns: `Status | Size | Path`
   - **Nuclei** → colored bullet list, sorted highest → lowest severity
     - CRITICAL = deep red
     - HIGH = orange
     - MEDIUM = dark yellow
     - LOW = blue
     - INFO = green
     - UNKNOWN = grey
   - **Nikto** → bullet list of every vulnerability item (header noise filtered out)
3. **Raw Output** — the complete raw tool output (long lines truncated at 200 chars)

---

## 9. Tool Commands Reference

### Dirsearch

```bash
dirsearch -u {url} \
  -r --random-agent --crawl --full-url -i 200,310,302 \
  -e php,html,js,txt,bak,zip,conf \
  -w /usr/share/wordlists/dirb/common.txt \
  -o {output}
```

- Wordlist: `/usr/share/wordlists/dirb/common.txt` (ships with Kali)
- Included status codes: 200, 310, 302
- No `--format` flag — format is auto-detected from the `.txt` extension
- No `--quiet` flag — older dirsearch builds don't support it

### Nuclei

```bash
nuclei -u '{url}' \
  -headless -project --timeout 30 -retries 2 \
  -o {output} \
  -silent -no-color
```

- **No `-severity` filter** → all severities reported
- No `-fr` / `-lfa` flags (they are not valid nuclei options)
- `-no-color` prevents ANSI escape codes from polluting the report
- `-silent` shows only findings

### Nikto

```bash
nikto -h {url} \
  -o {output} \
  -Format txt \
  -nointeractive \
  -timeout 15 \
  -followredirects \
  {ssl}
```

- **No `-Tuning` filter** → full test suite runs
- `{ssl}` becomes `-ssl` automatically when the target is HTTPS
- `-timeout 15` prevents hangs
- `-followredirects` handles 3xx redirects

---

## 10. Troubleshooting

### `error: externally-managed-environment` when running pip
You forgot to activate the venv:
```bash
source venv/bin/activate
pip install reportlab
```

### `'dirsearch' not found on PATH`
```bash
sudo apt install -y dirsearch
# or, if apt fails:
sudo apt install -y pipx
pipx ensurepath
pipx install dirsearch
# reopen terminal, then:
which dirsearch
```

### `'nuclei' not found on PATH`
```bash
sudo apt install -y nuclei
# or via Go:
sudo apt install -y golang-go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo ln -s ~/go/bin/nuclei /usr/local/bin/nuclei
```
Then update templates:
```bash
nuclei -update-templates
```

### `'nikto' not found on PATH`
```bash
sudo apt install -y nikto
```

### Nuclei finds nothing
Templates are missing or outdated:
```bash
nuclei -update-templates
nuclei -templates-version
```

### dirsearch error: `no such option: --format`
Your dirsearch build is older. The script already handles this — it does **not** use `--format`. Format is auto-picked from the `.txt` extension of the output file.

### Nikto is slow / appears to hang
The script passes `-timeout 15`. If your target is behind a slow WAF, increase it in the `COMMANDS` dict at the top of `recon_kali.py`.

### PDF report is not generated
Make sure `reportlab` is installed **inside the active venv**:
```bash
source venv/bin/activate
pip install reportlab
python -c "import reportlab; print('OK')"
```

### Script says "FAILED" for one tool but continues
This is by design. The script never aborts mid-run. Check the **Errors encountered** block on the first page of the PDF to see what went wrong.

### venv activation "disappears" every time I close the terminal
That's expected. You must run `source venv/bin/activate` **every time** you open a new terminal. If you want a shortcut, add an alias to `~/.bashrc`:
```bash
echo "alias recon='cd ~/recon-tool && source venv/bin/activate'" >> ~/.bashrc
source ~/.bashrc
# now you can type: recon
```

---

## 11. Notes & Warnings

- ⚖️ **Legal**: Only run this against systems you own or have **explicit written permission** to test. Unauthorized scanning is illegal in most jurisdictions.
- ⏱️ **Scan duration**: Nuclei with no severity filter runs **all** templates (~11,000+) and can take **15–45 minutes** depending on the target.
- 🌐 **Network load**: The scan sends thousands of requests. On production targets, schedule during off-hours or coordinate with the target owner.
- 🔁 **venv activation is required every session** — closing the terminal deactivates it.
- 📁 **Nuclei `-project` flag** creates a project folder inside the results directory to avoid duplicate requests.
- ⛔ **Ctrl+C** will abort the current tool and skip the PDF generation.
- 📜 **License**: For educational and authorized security testing use only.

---

## Quick Reference Card

```bash
# One-time setup
sudo apt update
sudo apt install -y dirsearch nuclei nikto python3-venv python3-pip
nuclei -update-templates
mkdir -p ~/recon-tool && cd ~/recon-tool
python3 -m venv venv
source venv/bin/activate
pip install reportlab
echo "reportlab>=4.0.0" > requirements.txt

# Every session
cd ~/recon-tool
source venv/bin/activate
python3 recon_kali.py
# ... enter target URL when prompted ...
deactivate
```

---

**That's it — you're ready to run reconnaissance on Kali Linux.**
