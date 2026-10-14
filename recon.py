#!/usr/bin/env python3
"""
Recon Automation Script for Kali Linux
- Creates a folder named after the target URL
- Runs dirsearch -> nuclei -> nikto ONE AFTER ANOTHER
- Pre-flight checks that each tool exists on PATH
- Strips ANSI color codes so the PDF report is clean
- On error in any step, prints the error and continues to the next step
- Produces a PDF report with, per tool:
    * Command line
    * Parsed "Findings" section (table / bullets)
    * Full raw output
"""

import os
import sys
import shutil
import subprocess
import datetime
import re
from pathlib import Path

# ---------- PDF library check ----------
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, PageBreak,
        Preformatted, Table, TableStyle, KeepTogether
    )
except ImportError:
    print("[!] reportlab is not installed. Install it with:  pip install reportlab")
    sys.exit(1)


# =====================================================================
#  COMMANDS  (edit here if you want different flags)
#  Use {url}    -> target URL
#  Use {output} -> raw output file path
#  Use {ssl}    -> "-ssl" if target is HTTPS, otherwise empty string
#
#  Nikto fix:
#   - Removed -Tuning 23b (it restricted Nikto to only 3 test categories).
#   - Added -ssl dynamically for HTTPS targets.
#   - Added -timeout 15 to avoid hanging.
#   - Added -followredirects to handle 3xx redirects.
#   - Kept -nointeractive, -Format txt.
# =====================================================================
COMMANDS = {
    "Dirsearch": (
        "dirsearch -u {url} "
        "-r --random-agent --crawl --full-url -i 200,310,302 "
        "-e php,html,js,txt,bak,zip,conf "
        "-w /usr/share/wordlists/dirb/common.txt "
        "-o {output}"
    ),
    "Nuclei": (
        "nuclei -u '{url}' "
        "-headless -project --timeout 30 -retries 2 "
        "-o {output} "
        "-silent -no-color"
    ),
    "Nikto": (
        "nikto -h {url} "
        "-o {output} "
        "-Format txt "
        "-nointeractive "
        "-timeout 15 "
        "-followredirects "
        "{ssl}"
    ),
}

TOOL_BINARIES = {
    "Dirsearch": "dirsearch",
    "Nuclei": "nuclei",
    "Nikto": "nikto",
}

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


# ---------- Generic helpers ----------
def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def esc(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


def sanitize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url


def url_to_slug(url: str) -> str:
    s = url.replace("https://", "").replace("http://", "")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return s.rstrip("_") or "target"


def unique_folder(base: Path) -> Path:
    if not base.exists():
        return base
    i = 1
    while True:
        cand = base.with_name(f"{base.name}_{i}")
        if not cand.exists():
            return cand
        i += 1


def truncate_lines(text: str, max_len: int = 200) -> str:
    out = []
    for line in text.splitlines():
        if len(line) > max_len:
            line = line[:max_len] + " ... [truncated]"
        out.append(line)
    return "\n".join(out)


# ---------- Tool-specific parsers ----------
def parse_dirsearch(text: str):
    """Extract (status, size, path) tuples from dirsearch plain output."""
    results = []
    pat = re.compile(
        r"\[(\d{2}:\d{2}:\d{2})\]\s+(\d{3})\s+-\s+([\d.]+\s*\w*)\s+-\s+(\S+)"
    )
    for line in text.splitlines():
        m = pat.search(line)
        if m:
            results.append((m.group(2), m.group(3).strip(), m.group(4)))
    return results


def parse_nuclei(text: str):
    """Extract (severity, template_id, protocol, url, extra) tuples."""
    results = []
    pat = re.compile(
        r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)$"
    )
    for line in text.splitlines():
        m = pat.match(line.strip())
        if m:
            tpl, proto, sev, url, extra = m.groups()
            results.append((sev.lower(), tpl, proto, url, extra.strip()))
    return results


def parse_nikto(text: str):
    """
    Extract Nikto findings (lines starting with '+ ') while skipping
    meta-information lines (Target IP, Start Time, End Time, etc.).
    """
    SKIP_PREFIXES = (
        "Target IP:", "Target Hostname:", "Target Port:",
        "Start Time:", "End Time:", "Server:", "requests:",
        "SSL Info:", "No web server found",
    )
    items = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("+ "):
            continue
        content = s[2:].strip()
        if any(content.startswith(p) for p in SKIP_PREFIXES):
            continue
        items.append(content)
    return items


# ---------- Command runner ----------
def run_command(name: str, cmd: str, raw_file: Path, cwd: Path,
                index: int, total: int):
    print("\n" + "=" * 62)
    print(f"  [{index}/{total}]  RUNNING  {name.upper()}  ...")
    print("=" * 62)
    print(f"[*] Command : {cmd}")
    print(f"[*] Output  : {raw_file}")
    print("-" * 62)

    binary = TOOL_BINARIES.get(name, name.lower())
    if shutil.which(binary) is None:
        err_msg = (f"'{binary}' not found on PATH. "
                   f"Install it (e.g. 'sudo apt install {binary}' or "
                   f"'pipx install dirsearch') and try again.")
        print(f"[!] {err_msg}")
        raw_file.write_text(f"[!] {err_msg}\n", encoding="utf-8")
        return False, err_msg

    ok = False
    err_msg = ""

    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=str(cwd),
        )

        with raw_file.open("w", encoding="utf-8", errors="ignore") as f:
            assert proc.stdout is not None
            for line in proc.stdout:
                clean = strip_ansi(line)
                sys.stdout.write(clean)
                sys.stdout.flush()
                f.write(clean)

        try:
            proc.wait(timeout=3600)
        except subprocess.TimeoutExpired:
            proc.kill()
            err_msg = f"{name} timed out after 1 hour"
            print(f"\n[!] {err_msg}")
            with raw_file.open("a", encoding="utf-8") as f:
                f.write(f"\n[!] {err_msg}\n")
            return False, err_msg

        if proc.returncode == 0:
            ok = True
            print(f"\n[+] {name} completed successfully (exit 0).")
        else:
            err_msg = f"{name} exited with code {proc.returncode}"
            print(f"\n[!] {err_msg}")
            with raw_file.open("a", encoding="utf-8") as f:
                f.write(f"\n[!] {err_msg}\n")

    except Exception as e:
        err_msg = f"Error running {name}: {e}"
        print(f"\n[!] {err_msg}")
        try:
            with raw_file.open("a", encoding="utf-8") as f:
                f.write(f"\n[!] {err_msg}\n")
        except Exception:
            pass

    if not ok:
        print(f"[*] Continuing to next step despite the {name} error ...")
    return ok, err_msg


def read_output(path: Path, max_chars: int = 400_000) -> str:
    if not path.exists():
        return "[!] No output file was produced."
    txt = path.read_text(encoding="utf-8", errors="ignore").strip()
    txt = strip_ansi(txt)
    if not txt:
        return "[!] Command produced no output."
    if len(txt) > max_chars:
        txt = txt[:max_chars] + "\n\n[... output truncated for report ...]"
    return txt


# ---------- PDF building blocks ----------
SEV_COLORS = {
    "critical": "#b00020",
    "high":     "#d35400",
    "medium":   "#b7950b",
    "low":      "#1f618d",
    "info":     "#1e8449",
    "unknown":  "#555555",
}

SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def make_dirsearch_table(findings):
    if not findings:
        return None
    data = [["Status", "Size", "Path"]]
    for status, size, path in findings:
        data.append([status, size, esc(path)])
    t = Table(data, colWidths=[2.0*cm, 2.2*cm, 12.0*cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b6e99")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",   (0, 1), (-1, -1), "Courier"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
            [colors.white, colors.HexColor("#f4f8fb")]),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
    ]))
    return t


def make_nuclei_list(findings, body_style):
    if not findings:
        return None
    sorted_findings = sorted(
        findings,
        key=lambda f: SEV_ORDER.index(f[0]) if f[0] in SEV_ORDER else len(SEV_ORDER)
    )
    flow = []
    for sev, tpl, proto, url, extra in sorted_findings:
        c = SEV_COLORS.get(sev, SEV_COLORS["unknown"])
        line = (f"<font color='{c}'><b>[{esc(sev.upper())}]</b></font> "
                f"<b>{esc(tpl)}</b> <i>({esc(proto)})</i><br/>"
                f"&nbsp;&nbsp;&nbsp;&nbsp;{esc(url)}")
        if extra:
            line += f"<br/>&nbsp;&nbsp;&nbsp;&nbsp;<font color='#555555'>{esc(extra)}</font>"
        flow.append(Paragraph(line, body_style))
        flow.append(Spacer(1, 4))
    return flow


def make_nuclei_severity_breakdown(findings):
    if not findings:
        return None
    counts = {}
    for sev, *_ in findings:
        counts[sev] = counts.get(sev, 0) + 1

    rows = [sev for sev in SEV_ORDER if counts.get(sev)]
    for sev in counts:
        if sev not in SEV_ORDER and counts[sev]:
            rows.append(sev)

    if not rows:
        return None

    data = [["Severity", "Count"]]
    for sev in rows:
        data.append([sev.upper(), str(counts[sev])])

    t = Table(data, colWidths=[4.0*cm, 2.5*cm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3b5d")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
        ("ALIGN",      (1, 0), (1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, sev in enumerate(rows, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i),
                      colors.HexColor(SEV_COLORS.get(sev, SEV_COLORS["unknown"]))))
    t.setStyle(TableStyle(style))
    return t


def make_nikto_list(items, body_style):
    if not items:
        return None
    flow = []
    for it in items:
        flow.append(Paragraph(f"• {esc(it)}", body_style))
    return flow


# ---------- PDF ----------
def build_pdf(report_path: Path, url: str, results: dict,
              started_at: str, ended_at: str, folder: Path):
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=20,
                        textColor=colors.HexColor("#1a3b5d"), spaceAfter=14)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=16,
                        textColor=colors.HexColor("#0b6e99"),
                        spaceBefore=18, spaceAfter=10)
    h3 = ParagraphStyle("H3", parent=styles["Heading3"], fontSize=12,
                        textColor=colors.HexColor("#1a3b5d"),
                        spaceBefore=10, spaceAfter=6)
    body = ParagraphStyle("Body", parent=styles["BodyText"],
                          fontSize=10, leading=13)
    finding = ParagraphStyle("Finding", parent=styles["BodyText"],
                             fontSize=9, leading=12)
    mono = ParagraphStyle("Mono", parent=styles["Code"],
                          fontSize=8, leading=10,
                          textColor=colors.HexColor("#222222"))
    small = ParagraphStyle("Small", parent=styles["BodyText"],
                           fontSize=8, leading=10,
                           textColor=colors.HexColor("#555555"))

    doc = SimpleDocTemplate(str(report_path), pagesize=A4,
                            leftMargin=1.6*cm, rightMargin=1.6*cm,
                            topMargin=1.6*cm, bottomMargin=1.6*cm,
                            title=f"Recon Report - {url}")

    story = []

    # ---------- Cover ----------
    story.append(Paragraph("Reconnaissance Report", h1))
    story.append(Paragraph(f"<b>Target:</b> {esc(url)}", body))
    story.append(Paragraph(f"<b>Results folder:</b> {esc(str(folder))}", body))
    story.append(Paragraph(f"<b>Scan started:</b> {started_at}", body))
    story.append(Paragraph(f"<b>Scan finished:</b> {ended_at}", body))
    story.append(Paragraph("<b>Tools:</b> " + ", ".join(COMMANDS.keys()), body))
    story.append(Paragraph("<b>Platform:</b> Kali Linux", body))
    story.append(Paragraph(
        "<b>Note:</b> nuclei runs with no severity filter (all severities "
        "included). Nikto runs with its full test suite (no -Tuning filter).",
        small))
    story.append(Spacer(1, 12))

    # ---------- Summary ----------
    story.append(Paragraph("Summary of Findings", h2))

    counts = {}
    for tool, data in results.items():
        txt = data["text"]
        if tool == "Dirsearch":
            counts[tool] = len(parse_dirsearch(txt))
        elif tool == "Nuclei":
            counts[tool] = len(parse_nuclei(txt))
        elif tool == "Nikto":
            counts[tool] = len(parse_nikto(txt))
        else:
            counts[tool] = 0

    summ_data = [["Tool", "Status", "Findings", "Raw output (chars)"]]
    for tool, data in results.items():
        summ_data.append([
            tool,
            "OK" if data["ok"] else "FAILED",
            str(counts.get(tool, 0)),
            str(len(data["text"])),
        ])
    st = Table(summ_data, colWidths=[3.5*cm, 2.5*cm, 2.5*cm, 4.5*cm], repeatRows=1)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3b5d")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
            [colors.white, colors.HexColor("#f4f8fb")]),
        ("ALIGN",      (1, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(st)

    # Nuclei severity breakdown
    nuclei_findings = parse_nuclei(results.get("Nuclei", {}).get("text", ""))
    breakdown = make_nuclei_severity_breakdown(nuclei_findings)
    if breakdown:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Nuclei severity breakdown", h3))
        story.append(breakdown)

    # Errors
    err_lines = []
    for tool, data in results.items():
        if not data["ok"] and data.get("error"):
            err_lines.append(f"• <b>{tool}</b>: {esc(data['error'])}")
    if err_lines:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Errors encountered", h3))
        for l in err_lines:
            story.append(Paragraph(l, body))

    story.append(PageBreak())

    # ---------- Per-tool sections ----------
    for tool, data in results.items():
        story.append(Paragraph(f"{tool} Results", h2))
        story.append(Paragraph(
            f"<i>Command:</i> <font face='Courier'>{esc(data['cmd'])}</font>",
            body))
        if not data["ok"] and data.get("error"):
            story.append(Paragraph(
                f"<font color='#b00020'><b>Error:</b> {esc(data['error'])}</font>",
                body))
        story.append(Spacer(1, 8))

        story.append(Paragraph("Findings", h3))
        raw_text = data["text"]

        if tool == "Dirsearch":
            findings = parse_dirsearch(raw_text)
            if findings:
                story.append(Paragraph(
                    f"Discovered <b>{len(findings)}</b> path(s):", body))
                story.append(Spacer(1, 6))
                story.append(make_dirsearch_table(findings))
            else:
                story.append(Paragraph(
                    "No paths were extracted from the output.", small))

        elif tool == "Nuclei":
            findings = parse_nuclei(raw_text)
            if findings:
                story.append(Paragraph(
                    f"Triggered <b>{len(findings)}</b> template(s) "
                    f"(sorted by severity, highest first):", body))
                story.append(Spacer(1, 6))
                for p in make_nuclei_list(findings, finding):
                    story.append(p)
            else:
                story.append(Paragraph(
                    "No nuclei findings extracted from the output.", small))

        elif tool == "Nikto":
            items = parse_nikto(raw_text)
            if items:
                story.append(Paragraph(
                    f"Nikto reported <b>{len(items)}</b> item(s):", body))
                story.append(Spacer(1, 6))
                for p in make_nikto_list(items, finding):
                    story.append(p)
            else:
                story.append(Paragraph(
                    "No Nikto findings extracted from the output.", small))

        story.append(Spacer(1, 14))

        story.append(Paragraph("Raw Output", h3))
        safe = esc(truncate_lines(raw_text))
        story.append(Preformatted(safe, mono))

        story.append(PageBreak())

    doc.build(story)


# ---------- Main ----------
def main():
    print("=" * 62)
    print("  Recon Automation — Kali Linux Edition")
    print("  dirsearch -> nuclei -> nikto   (sequential, error-tolerant)")
    print("=" * 62)

    url_input = input("Enter target URL (e.g. https://example.com): ").strip()
    if not url_input:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    url = sanitize_url(url_input)
    slug = url_to_slug(url)

    # Detect HTTPS for Nikto
    is_https = url.lower().startswith("https://")
    ssl_flag = "-ssl" if is_https else ""

    base_dir = unique_folder(Path.cwd() / slug)
    base_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Results folder: {base_dir}")

    started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    tools = list(COMMANDS.items())
    total = len(tools)
    results = {}

    for idx, (tool, cmd_template) in enumerate(tools, start=1):
        raw_file = base_dir / f"{tool.lower()}_raw.txt"
        cmd = cmd_template.format(url=url, output=str(raw_file), ssl=ssl_flag)
        ok, err = run_command(tool, cmd, raw_file, base_dir, idx, total)
        results[tool] = {
            "ok": ok,
            "error": err,
            "cmd": cmd,
            "text": read_output(raw_file),
        }

    ended_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_path = base_dir / f"recon_report_{slug}.pdf"
    print(f"\n[*] Building PDF report -> {report_path}")
    try:
        build_pdf(report_path, url, results, started_at, ended_at, base_dir)
    except Exception as e:
        print(f"[!] Failed to build PDF: {e}")
        sys.exit(1)

    print("\n" + "=" * 62)
    print("[+] Done.")
    print(f"[+] Report : {report_path}")
    print(f"[+] Raw outputs in: {base_dir}")
    print("=" * 62)


if __name__ == "__main__":
    main()