# SQLite database layer for the OSINT dashboard.

# Schema (6 tables):
#  scans              — Scan metadata (id, target, scan_date)
#  whois_results      — WHOIS lookup results
#  cert_results       — Certificate transparency / subdomain data
#  shodan_results     — Exposed services from Shodan
#  email_results      — Harvested email addresses
#  dns_results        — DNS records (A, AAAA, MX, TXT, NS, CNAME)

# All result tables use a FOREIGN KEY back to scans(id).


import sqlite3
from datetime import datetime

DB_PATH = "database/osint.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS shodan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            port INTEGER,
            service TEXT,
            banner TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS cert_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            subdomain TEXT,
            issuer TEXT,
            not_before TEXT,
            not_after TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS whois_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            registrar TEXT,
            creation_date TEXT,
            expiration_date TEXT,
            name_servers TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS email_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            email TEXT,
            source TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS dns_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            record_type TEXT,
            value TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)

    conn.commit()
    conn.close()


def create_scan(target):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (target, scan_date) VALUES (?, ?)",
        (target, datetime.utcnow().isoformat())
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_all_scans():
    """Return all scans ordered by date descending (newest first)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, scan_date FROM scans ORDER BY scan_date DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_details(scan_id):
    """Return a complete scan record (scan info + all module results) as a dict, or None."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return None

    cursor.execute("SELECT * FROM whois_results WHERE scan_id = ?", (scan_id,))
    whois_row = cursor.fetchone()

    cursor.execute("SELECT * FROM cert_results WHERE scan_id = ?", (scan_id,))
    certs = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM shodan_results WHERE scan_id = ?", (scan_id,))
    shodan = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM email_results WHERE scan_id = ?", (scan_id,))
    emails = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT record_type, value FROM dns_results WHERE scan_id = ?", (scan_id,))
    dns_rows = cursor.fetchall()

    conn.close()

    whois_data = dict(whois_row) if whois_row else {
        "registrar": "N/A", "creation_date": "N/A",
        "expiration_date": "N/A", "name_servers": "N/A"
    }

    dns_records = {}
    for row in dns_rows:
        dns_records.setdefault(row["record_type"], []).append(row["value"])

    dns_data = {"records": dns_records, "error": None} if dns_rows else None

    return {
        "scan_id": scan_id,
        "target": scan["target"],
        "scan_date": scan["scan_date"],
        "whois": whois_data,
        "certs": certs,
        "shodan": shodan,
        "emails": emails,
        "dns": dns_data,
    }


def get_subdomain_trend(target):
    """Returns a list of {scan_date, subdomain_count} for a given target, ordered by date."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT s.scan_date, COUNT(c.id) as subdomain_count
        FROM scans s
        LEFT JOIN cert_results c ON c.scan_id = s.id
        WHERE s.target = ?
        GROUP BY s.id
        ORDER BY s.scan_date ASC
    """, (target,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_previous_scan(scan_id, target):
    """Returns the id of the most recent prior scan of the same target, or None."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM scans
        WHERE target = ? AND id < ?
        ORDER BY id DESC
        LIMIT 1
    """, (target, scan_id))
    row = cursor.fetchone()
    conn.close()
    return row["id"] if row else None


def get_scan_diff(current_id, previous_id):
    """Compares subdomains and DNS records between two scans of the same target."""
    current = get_scan_details(current_id)
    previous = get_scan_details(previous_id)

    # Subdomains
    current_subs = {c["subdomain"] for c in current["certs"]}
    previous_subs = {c["subdomain"] for c in previous["certs"]}

    new_subs = sorted(current_subs - previous_subs)
    removed_subs = sorted(previous_subs - current_subs)

    # DNS records
    def get_dns_set(scan_id, exclude_txt=False):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT record_type, value FROM dns_results WHERE scan_id = ?", (scan_id,))
        rows = cursor.fetchall()
        conn.close()
        if exclude_txt:
            rows = [r for r in rows if r["record_type"] != "TXT"]
        return {f"{r['record_type']}: {r['value']}" for r in rows}

    current_dns_all = get_dns_set(current_id)
    previous_dns_all = get_dns_set(previous_id)

    # If the previous scan has no DNS data at all, skip the DNS diff
    dns_diff_available = len(previous_dns_all) > 0

    new_dns, removed_dns, new_txt, removed_txt = [], [], [], []
    if dns_diff_available:
        current_core = get_dns_set(current_id, exclude_txt=True)
        previous_core = get_dns_set(previous_id, exclude_txt=True)
        new_dns = sorted(current_core - previous_core)
        removed_dns = sorted(previous_core - current_core)

        current_txt = {v for v in current_dns_all if v.startswith("TXT:")} - current_core
        previous_txt = {v for v in previous_dns_all if v.startswith("TXT:")} - previous_core
        new_txt = sorted(current_txt - previous_txt)
        removed_txt = sorted(previous_txt - current_txt)

    return {
        "previous_scan_id": previous_id,
        "previous_scan_date": previous["scan_date"],
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "dns_diff_available": dns_diff_available,
        "new_dns": new_dns,
        "removed_dns": removed_dns,
        "new_txt": new_txt,
        "removed_txt": removed_txt,
    }


def remove_history():
    """Delete ALL rows from every table — irreversibly clears scan history."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executescript("""
        DELETE FROM shodan_results;
        DELETE FROM cert_results;
        DELETE FROM whois_results;
        DELETE FROM email_results;
        DELETE FROM dns_results;
        DELETE FROM scans;
    """)
    conn.commit()
    conn.close()


def get_dashboard_stats():
    """Run 9 aggregate queries and return a flat dict of dashboard KPIs.

    Returns:
        total_scans, total_targets, total_dns, total_subdomains,
        total_services, total_emails, scans_today, recent_scans (list),
        last_scan (dict or None), top_services (list), dns_breakdown (list), max_dns
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT target) FROM scans")
    total_targets = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM dns_results")
    total_dns = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cert_results")
    total_subdomains = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM shodan_results")
    total_services = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM email_results")
    total_emails = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE scan_date >= datetime('now', '-1 day')")
    scans_today = cursor.fetchone()[0]
    cursor.execute("SELECT id, target, scan_date FROM scans ORDER BY scan_date DESC LIMIT 5")
    recent_scans = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT id, target, scan_date FROM scans ORDER BY scan_date DESC LIMIT 1")
    last = cursor.fetchone()
    cursor.execute("""
        SELECT service, COUNT(*) as cnt
        FROM shodan_results
        GROUP BY service
        ORDER BY cnt DESC
        LIMIT 7
    """)
    top_services = [dict(r) for r in cursor.fetchall()]
    cursor.execute("""
        SELECT record_type, COUNT(*) as cnt
        FROM dns_results
        GROUP BY record_type
        ORDER BY cnt DESC
    """)
    dns_breakdown = [dict(r) for r in cursor.fetchall()]
    max_dns = max((r["cnt"] for r in dns_breakdown), default=0)
    conn.close()
    return {
        "total_scans": total_scans,
        "total_targets": total_targets,
        "total_dns": total_dns,
        "total_subdomains": total_subdomains,
        "total_services": total_services,
        "total_emails": total_emails,
        "scans_today": scans_today,
        "recent_scans": recent_scans,
        "last_scan": dict(last) if last else None,
        "top_services": top_services,
        "dns_breakdown": dns_breakdown,
        "max_dns": max_dns,
    }