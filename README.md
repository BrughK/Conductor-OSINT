# Conductor OSINT Dashboard

A web-based Open Source Intelligence (OSINT) reconnaissance tool that gathers publicly available information about a target domain. Runs five intelligence-gathering modules and displays results in a single HUD-style dashboard with interactive charts, trend analysis, and exportable reports.

## Motivation

This project was developed to demonstrate practical cybersecurity development skills through the creation of a real-world OSINT platform. As I work toward an entry-level cybersecurity role, I wanted to build an application that goes beyond tutorials and showcases my ability to design, develop, and maintain a complete solution.

The dashboard centralizes open-source intelligence gathering and visualization into a single interface, highlighting concepts commonly used in threat intelligence and security investigations. Through this project, I gained experience with full-stack development, API integration, data processing, and user-focused design while creating a portfolio project that reflects my passion for cybersecurity.

## Table of Contents

- [Tech Stack](#tech-stack)
- [Features](#features)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Modules](#modules)
- [Routes](#routes)
- [Notes](#notes)
- [License](#license)

## Tech Stack

- **Backend:** Python, Flask, ReportLab (PDF export)
- **Database:** SQLite
- **Frontend:** Tailwind CSS v3 (CDN), Chart.js 4.4, Google Fonts (Space Grotesk, Inter, JetBrains Mono)
- **OSINT:** python-whois, crt.sh API, Shodan API (mock/demo mode), dnspython

## Features

- **Multi-module scanning** — WHOIS lookup, Certificate Transparency (crt.sh), Shodan exposed services, DNS records (A, AAAA, MX, TXT, NS, CNAME), and email harvesting
- **HUD-style dashboard** — KPI cards (Targets, DNS Records, Subdomains, Services, Emails, Today), last-target spotlight, recent-scans table
- **Interactive charts** — Chart.js donut for service distribution, CSS horizontal bars for DNS record breakdown, bar/pie/line charts on detailed views
- **Persistent history** — All scan results stored in SQLite with full detail review
- **Trend analysis** — Subdomain count line chart across all scans of the same target
- **Scan diff** — New/removed subdomains and DNS records between successive scans (TXT changes in a collapsible group)
- **CSV & PDF export** — Export any scan report as CSV or a formatted PDF with ReportLab
- **Retry mechanism** — Re-run crt.sh certificate lookup on demand
- **Dark/light theme** — Toggle with localStorage persistence, system default detection, constellation background adapts
- **Copy to clipboard** — One-click copy on certificate subdomains and emails
- **Delete all scans** — Red confirmation button on the history page with toast notification
- **Real-time scan progress** — Polling-based status updates during scans with animated train on tracks

## Quick Start

1. **Prerequisites** — Python 3.14+

2. **Clone the repo**

   ```bash
   git clone https://github.com/yourusername/osint-dashboard.git
   cd osint-dashboard
   ```

3. **Create and activate a virtual environment**

   ```bash
   python -m venv venv
   venv\Scripts\activate        # Windows
   # source venv/bin/activate   # macOS/Linux
   ```

4. **Install dependencies**

   ```bash
   pip install Flask python-whois requests python-dateutil dnspython reportlab
   ```

5. **(Optional) Set your Shodan API key**

   ```bash
   export SHODAN_API_KEY="your_key_here"    # macOS/Linux
   set SHODAN_API_KEY=your_key_here       # Windows
   ```

   Without this, the Shodan module returns realistic mock data.

6. **Run the app**

   ```bash
   python app.py
   ```

7. Open **http://localhost:5000** in your browser.

## Project Structure

```
osint-dashboard/
├── app.py                         # Flask entry point: routes, scan orchestration, CSV/PDF export
├── database/
│   └── db.py                      # SQLite schema, CRUD, dashboard stats, trend/diff queries
├── modules/
│   ├── __init__.py
│   ├── whois_lookup.py            # WHOIS via python-whois
│   ├── crt_lookup.py              # Certificate Transparency via crt.sh API
│   ├── shodan_lookup.py           # Shodan exposed services (mock data by default)
│   ├── dns_lookup.py              # DNS records via dnspython (A, AAAA, MX, TXT, NS, CNAME)
│   └── email_harvester.py         # Email scraping from website + certificate fields
├── templates/
│   ├── base.html                  # Base layout: sidebar w/ collapse, nav, theme toggle, toast, constellations
│   ├── index.html                 # HUD dashboard: KPI cards, spotlight, recent scans, charts
│   ├── new_scan.html              # Scan form page (separate from dashboard)
│   ├── scanning.html              # Train animation progress page
│   ├── results.html               # Live scan results: WHOIS, DNS, Shodan, certs, emails, charts
│   ├── history.html               # Past scans list with delete-all button
│   └── history_detail.html        # Archived scan view with diff and trend chart
└── static/
    ├── favicon.svg                # Train SVG favicon (32×32)
    └── js/                        # (currently unused)
```

## Modules

| Module          | Source                                | Data Collected                                     |
| --------------- | ------------------------------------- | -------------------------------------------------- |
| WHOIS           | `python-whois` library                | Registrar, creation/expiration dates, name servers |
| crt.sh          | Certificate Transparency log API      | Subdomains, issuers, validity dates                |
| Shodan          | Shodan API (mock data without key)    | IP, port, service banner                           |
| DNS             | `dnspython`                           | A, AAAA, MX, TXT, NS, CNAME records                |
| Email Harvester | Website scraping + certificate fields | Email addresses with source attribution            |

## Routes

| Method | Path                  | Description                       |
| ------ | --------------------- | --------------------------------- |
| GET    | `/`                   | Dashboard with KPI cards, charts  |
| GET    | `/scan`               | New scan page (form)              |
| POST   | `/scan`               | Start a new scan                  |
| GET    | `/scan_status/<uuid>` | Poll scan progress (JSON)         |
| GET    | `/scan_result/<uuid>` | View scan results                 |
| GET    | `/chart_data/<uuid>`  | Chart data (JSON)                 |
| GET    | `/retry_certs/<uuid>` | Retry crt.sh lookup               |
| GET    | `/history`            | All past scans                    |
| POST   | `/history/delete_all` | Delete all scan history           |
| GET    | `/history/<id>`       | Historical scan details with diff |
| GET    | `/export/<id>/csv`    | Export scan as CSV                |
| GET    | `/export/<id>/pdf`    | Export scan as PDF report         |

## Notes

- Designed for local/educational use — no authentication, rate limiting, or CSRF protection
- Flask runs in debug mode on port 5000
- In-memory scan progress tracking (lost on server restart)
- Modules run serially in a single background thread
- Tailwind CSS is loaded via CDN; custom `@keyframes` in `<head>` are overridden by Tailwind's runtime stylesheet, so animation declarations require `!important` in a bottom `<style>` block
- The constellation background is a `<canvas>` at `z-index: 0` with `pointer-events: none`; page content sits at `z-index: 1`
- The sidebar collapses to icon-only mode (64px wide) via a toggle button in the footer; text labels are hidden and nav link `title` attributes serve as hover tooltips
- Sidebar collapse state is persisted in `localStorage` under the key `sidebar-collapsed`
- Shodan module returns realistic mock data by default; set `SHODAN_API_KEY` for live API data

| Variable         | Description                                         |
| ---------------- | --------------------------------------------------- |
| `SHODAN_API_KEY` | Set to use the real Shodan API instead of mock data |

## License

This project is licensed under the MIT license.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![Python](https://img.shields.io/badge/python-3.14+-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
