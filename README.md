# PhishLens — Phishing / Fake Login Page Detector (Python)

 ```
 ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
 ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║     ██╔════╝████╗  ██║██╔════╝
 ██████╔╝███████║██║███████╗███████║██║     █████╗  ██╔██╗ ██║███████╗
 ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║     ██╔══╝  ██║╚██╗██║╚════██║
 ██║     ██║  ██║██║███████║██║  ██║███████╗███████╗██║ ╚████║███████║
 ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
 ```

 PhishLens is a **job-ready**, Python-based phishing page detector that performs **static analysis** on HTML (local files or fetched URLs) and generates a **risk score** plus **explainable findings**. It is designed to reduce false-positives on large legitimate websites (Facebook/Google-style pages) using **per-rule caps**, **diminishing returns**, and **wildcard allowlists**.

 ---
 
 ## Table of contents
 - Overview
 - Threat model (scope)
 - Install
 - Quick start
 - CLI usage (`scan`, `scan-url`)
 - Banner styles
 - Stylish terminal output
 - Allowlist (wildcards)
 - Reports (JSON + HTML)
 - Plugins (custom rules)
 - Tuning tips (reduce false positives)
 - Safety notes
 - Author / contact
 
 ---
 
 ## Overview
 PhishLens inspects a single HTML page and looks for phishing signals commonly seen in credential-harvesting pages, skimmers, and phishing kits. It does **not** attempt to “crawl the web” or execute JavaScript; instead it focuses on **fast, explainable heuristics** that you can use in IR triage, SOC workflows, or personal analysis.

 ## Why this is job-ready
 PhishLens is designed like a practical security tool: it uses a rule engine with severity + weights, produces an explainable score with evidence (useful for triage and reporting), supports scanning both local HTML and fetched URLs, and provides machine-readable JSON + shareable HTML reports. To reduce false positives on modern legitimate web apps (Facebook/Google-style pages), it applies per-rule contribution caps and diminishing returns, and it supports wildcard allowlists (example: `*.fbcdn.net`) so trusted CDNs and first-party subdomains do not inflate risk scores.

 It outputs:
 - A **score** from `0` to `100`
 - A **rating** (`low_risk`, `medium_risk`, `high_risk`)
 - A list of **findings** (rule id, severity, evidence)
 - Optional **reports** in JSON and/or HTML

 ---
 
 ## Threat model (scope)
 - **Input**
   You scan local HTML files/folders, or fetch a single URL with `scan-url` and scan the fetched HTML.
 - **Output**
   You get a risk score + explainable findings (why the page looks suspicious).
 - **Important limitation**
   No JS execution, no crawling. This is intentional (safe, fast, explainable), but it means some SPA-rendered login forms may not be visible in the static HTML.

 ---
 
 ## Install
 
 ```bash
 python -m pip install -r requirements.txt
 ```
 
 Dependencies:
 - `beautifulsoup4` for HTML parsing
 - `rich` for stylish terminal output (CLI falls back to plain output if not available)

 ---
 
 ## Quick start
 
 Scan the included samples:
 
 ```bash
 python -m phishlens scan samples/phish_like.html --base-url https://example.com
 python -m phishlens scan samples/legit_like.html --base-url https://example.com
 ```
 
 Run unit tests:
 
 ```bash
 python -m unittest
 ```
 
 ---
 
 ## CLI usage
 
 ### `scan` (local file / folder)
 
 Scan a single file:
 
 ```bash
 python -m phishlens scan samples/phish_like.html --base-url https://accounts.example.com
 ```
 
 Scan a folder:
 
 ```bash
 python -m phishlens scan samples --base-url https://accounts.example.com
 ```
 
 Control report output:
 
 ```bash
 python -m phishlens scan samples/phish_like.html --base-url https://accounts.example.com --format both --out-dir reports
 ```
 
 ### `scan-url` (fetch a URL, then analyze)
 
 **Do not enter credentials.** This is a scanner, not a login tool.
 
 ```bash
 python -m phishlens scan-url "https://example.com/login" --base-url https://example.com
 ```
 
 Save JSON only into an `out/` folder:
 
 ```bash
 python -m phishlens scan-url "https://example.com/login" --base-url https://example.com --format json --out-dir out
 ```
 
 Common options:
 - `--base-url`
   Used for domain comparisons. If omitted in `scan-url`, it is derived from the final fetched URL.
 - `--timeout`
   Fetch timeout (seconds).
 - `--max-bytes`
   Max bytes to download.

 ---

 ## Banner styles
 PhishLens can show an ASCII banner on every run. By default it uses `--banner random`, so the banner changes each time you run the tool.

 Use:

 ```bash
 python -m phishlens --banner random scan samples/phish_like.html --base-url https://example.com
 python -m phishlens --banner b3 scan samples/phish_like.html --base-url https://example.com
 python -m phishlens --banner none scan samples/phish_like.html --base-url https://example.com
 ```

 Supported values:
 - `random` (default)
 - `none`
 - `b1` .. `b10`

 ---
 
 ## Stylish terminal output
 The CLI prints a GitHub-friendly summary panel + a findings table.

 Example (sample phishing-like page):
 
 ```text
 ╭────────────────────────────────────────╮
 │ samples\phish_like.html                │
 │ score 100/100  |  rating high_risk     │
 │ base_domain example.com  |  findings 8 │
 ╰────────────────────────────────────────╯
 ```
 
 If `rich` is not installed, PhishLens automatically falls back to plain text output.

 ---

 ## Examples (real scans)

 ### Example 1: Local sample (phishing-like)
 
 ```bash
 python -m phishlens scan samples/phish_like.html --base-url https://example.com
 ```

 Example output:

 ```text
 ╭────────────────────────────────────────╮
 │ samples\phish_like.html                │
 │ score 100/100  |  rating high_risk     │
 │ base_domain example.com  |  findings 8 │
 ╰────────────────────────────────────────╯
 ```

 ### Example 2: Live URL + allowlist (reduce false positives)

 ```bash
 python -m phishlens scan-url "https://www.facebook.com/" --base-url https://www.facebook.com --allowlist facebook_allowlist.json --format json --out-dir out
 ```

 What you typically see on large legitimate sites: low risk with mostly minified/high-entropy inline JS findings (weak signal) and clean domain checks due to allowlisting.

 ### Example 3: Live URL (enterprise portal patterns)

 ```bash
 python -m phishlens scan-url "https://onlineservices.proteantech.in/paam/" --base-url https://onlineservices.proteantech.in --format json --out-dir out
 ```

 Typical findings can include localhost/private endpoint calls (device fingerprinting/local agent) and third-party CDN scripts. Treat these as risk signals and validate against expected vendor behavior.

 ---
 
 ## Allowlist (wildcards)
 Large legitimate web apps often load assets from CDNs and related domains. Use an allowlist to reduce false positives.

 Allowlist JSON format:
 
 ```json
 {
   "domains": [
     "accounts.example.com",
     "cdn.example.com",
     "*.static.example.com"
   ]
 }
 ```
 
 Run with allowlist:
 
 ```bash
 python -m phishlens scan-url "https://www.facebook.com/" --base-url https://www.facebook.com --allowlist facebook_allowlist.json --format json --out-dir out
 ```
 
 Notes:
 - Wildcards like `*.fbcdn.net` are supported.
 - Avoid overly broad entries (example: `*.com`). It can hide real red flags.

 ---
 
 ## Reports (JSON + HTML)
 By default, reports are written under `reports/` (you can change with `--out-dir`).

 - **JSON**
   Machine-readable output for automation, SOC pipelines, triage tools.
 - **HTML**
   Human-friendly report for quick review and sharing.

 Control formats:
 - `--format json`
 - `--format html`
 - `--format both`

 Example outputs:
 - `reports/samples_phish_like_html.json`
 - `reports/samples_phish_like_html.html`
 - `out/https___onlineservices_proteantech_in_paam_.json`

 ---
 
 ## Plugins (custom rules)
 PhishLens supports a plugin system so you can add custom detection logic without editing the core engine.

 Example:
 
 ```bash
 python -m phishlens scan samples/phish_like.html --base-url https://accounts.example.com --plugin plugins/example_rules.py
 ```
 
 Plugin contract (a plugin file must define either):
 - `get_rules() -> List[Rule]`
 - `RULES = [Rule(...), ...]`

 See `plugins/example_rules.py`.

 ---
 
 ## Tuning tips (reduce false positives)
 - Use `--base-url` correctly. A wrong base URL can inflate “external/mixed domains”.
 - Use `--allowlist` for known good CDNs and first-party subdomains.
 - Treat `JS_HIGH_ENTROPY_INLINE` as a **weak** signal; rely more on higher-confidence signals like:
   - External form actions
   - Insecure HTTP form actions
   - Obfuscation API usage in inline JS
   - Localhost/private IP calls from inline JS

 ---
 
 ## Safety notes
 PhishLens is for analysis only. Do **not** type real usernames or passwords into scanned pages, and only analyze URLs/pages that you are allowed to access. The output is a set of **risk signals** with evidence, not a guarantee—always validate domain ownership, certificate details, and the expected login flow.

 ---
 
 ## Author / contact
 **Mayur Jawanjar**

 Contact:
 - Email: `contact.thecyberwar@gmail.com`

 ---

 ## License
 MIT License. See `LICENSE`.
