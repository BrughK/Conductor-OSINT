import csv
import io
import re
import threading
import uuid

from flask import Flask, render_template, request, jsonify, Response, redirect, url_for
from database.db import (
    init_db,
    get_connection,
    create_scan,
    get_all_scans,
    get_scan_details,
    get_subdomain_trend,
    get_previous_scan,
    get_scan_diff,
    remove_history,
    get_dashboard_stats,
)
from modules.crt_lookup import get_certificates
from modules.dns_lookup import get_dns_records
from modules.email_harvester import get_emails
from modules.shodan_lookup import get_shodan_data
from modules.whois_lookup import get_whois
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)

# In-memory progress tracker: { scan_uuid: {"status": ..., "step": ..., "result": ...} }
scan_progress: dict = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def simplify_issuer(issuer_string: str) -> str:
    """Extract just the organization (O=…) from a full certificate DN string."""
    match = re.search(r'O=([^,]+)', issuer_string)
    return match.group(1) if match else issuer_string


def _save_results(scan_id, whois_data, cert_data, shodan_data, email_data, dns_data) -> None:
    """Persist all module results to SQLite after a scan completes."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO whois_results (scan_id, registrar, creation_date, expiration_date, name_servers)
        VALUES (?, ?, ?, ?, ?)
    """, (scan_id, whois_data.get("registrar"), whois_data.get("creation_date"),
          whois_data.get("expiration_date"), whois_data.get("name_servers")))

    for cert in cert_data.get("certs", []):
        cursor.execute("""
            INSERT INTO cert_results (scan_id, subdomain, issuer, not_before, not_after)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, cert["subdomain"], cert["issuer"], cert["not_before"], cert["not_after"]))

    for r in shodan_data.get("results", []):
        cursor.execute("""
            INSERT INTO shodan_results (scan_id, ip, port, service, banner)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, r["ip"], r["port"], r["service"], r["banner"]))

    for e in email_data.get("emails", []):
        cursor.execute("""
            INSERT INTO email_results (scan_id, email, source)
            VALUES (?, ?, ?)
        """, (scan_id, e["email"], e["source"]))

    for record_type, values in dns_data.get("records", {}).items():
        for value in values:
            cursor.execute("""
                INSERT INTO dns_results (scan_id, record_type, value)
                VALUES (?, ?, ?)
            """, (scan_id, record_type, value))

    conn.commit()
    conn.close()

def run_scan(scan_uuid: str, target: str) -> None:
    """Background worker: executes all 5 OSINT modules sequentially, then persists results.

    Two-phase architecture:
      1. Collect data from each module (runs serially in this background thread)
      2. Persist everything via _save_results() once all modules complete
    This keeps DB writes atomic and avoids partial results on module failure.
    """
    scan_progress[scan_uuid] = {"status": "running", "step": "Starting scan...", "result": None}

    scan_progress[scan_uuid]["step"] = "Querying WHOIS..."
    whois_data = get_whois(target)

    scan_progress[scan_uuid]["step"] = "Checking certificate transparency logs (crt.sh)..."
    cert_data = get_certificates(target)

    scan_progress[scan_uuid]["step"] = "Checking exposed services (Shodan)..."
    shodan_data = get_shodan_data(target)

    scan_progress[scan_uuid]["step"] = "Searching for exposed emails..."
    email_data = get_emails(target, cert_data=cert_data.get("certs"))
    
    scan_progress[scan_uuid]["step"] = "Querying DNS records..."
    dns_data = get_dns_records(target)

    scan_progress[scan_uuid]["step"] = "Saving results..."
    scan_id = create_scan(target)
    _save_results(scan_id, whois_data, cert_data, shodan_data, email_data, dns_data)

    scan_progress[scan_uuid]["status"] = "done"
    scan_progress[scan_uuid]["step"] = "Complete!"
    scan_progress[scan_uuid]["result"] = {
        "target": target,
        "whois": whois_data,
        "certs": cert_data,
        "shodan": shodan_data,
        "emails": email_data,
        "dns": dns_data,
    }

# ---------------------------------------------------------------------------
# scan workflow
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    stats = get_dashboard_stats()
    return render_template("index.html", **stats)

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        return render_template("new_scan.html")

    target = request.form.get("target", "").strip()

    if not target:
        return render_template("new_scan.html", error="Please enter a target domain.")

    scan_uuid = str(uuid.uuid4())
    thread = threading.Thread(target=run_scan, args=(scan_uuid, target))
    thread.start()

    return render_template("scanning.html", scan_uuid=scan_uuid, target=target)

@app.route("/scan_status/<scan_uuid>")
def scan_status(scan_uuid):
    progress = scan_progress.get(scan_uuid)
    if not progress:
        return jsonify({"status": "not_found"}), 404

    return jsonify({
        "status": progress["status"],
        "step": progress["step"],
    })

@app.route("/scan_result/<scan_uuid>")
def scan_result(scan_uuid):
    progress = scan_progress.get(scan_uuid)
    if not progress or progress["status"] != "done":
        return "Scan not ready", 404

    result = progress["result"]
    return render_template(
        "results.html",
        scan_uuid=scan_uuid,
        target=result["target"],
        whois=result["whois"],
        certs=result["certs"],
        shodan=result["shodan"],
        emails=result["emails"],
        dns=result["dns"],
    )

# ---------------------------------------------------------------------------
# chart & retry helpers
# ---------------------------------------------------------------------------

@app.route("/chart_data/<scan_uuid>")
def chart_data(scan_uuid):
    """Return JSON with service counts and top 5 certificate issuers for a completed scan."""
    progress = scan_progress.get(scan_uuid)
    if not progress or progress["status"] != "done":
        return jsonify({"error": "not ready"}), 404

    result = progress["result"]

    service_counts = {}
    for r in result["shodan"].get("results", []):
        service = r["service"]
        service_counts[service] = service_counts.get(service, 0) + 1

    issuer_counts = {}
    for c in result["certs"].get("certs", []):
        issuer = simplify_issuer(c["issuer"])
        issuer_counts[issuer] = issuer_counts.get(issuer, 0) + 1

    top_issuers = sorted(issuer_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return jsonify({
        "services": {
            "labels": list(service_counts.keys()),
            "data": list(service_counts.values()),
        },
        "issuers": {
            "labels": [i[0] for i in top_issuers],
            "data": [i[1] for i in top_issuers],
        },
    })

@app.route("/retry_certs/<scan_uuid>")
def retry_certs(scan_uuid):
    """Re-run crt.sh lookup for a completed scan and update the in-memory result in place."""
    progress = scan_progress.get(scan_uuid)
    if not progress or progress["status"] != "done":
        return jsonify({"error": "scan not found"}), 404

    target = progress["result"]["target"]
    cert_data = get_certificates(target)

    progress["result"]["certs"] = cert_data

    return jsonify(cert_data)

# ---------------------------------------------------------------------------
# history & export
# ---------------------------------------------------------------------------

@app.route("/history")
def history():
    scans = get_all_scans()
    return render_template("history.html", scans=scans)


@app.route("/history/delete_all", methods=["POST"])
def delete_all_history():
    remove_history()
    return redirect(url_for("history", deleted=1))


@app.route("/history/<int:scan_id>")
def history_detail(scan_id):
    """Show archived scan details with chart data, subdomain trend, and diff vs previous scan."""
    details = get_scan_details(scan_id)
    if not details:
        return "Scan not found", 404

    trend = get_subdomain_trend(details["target"])

    service_counts = {}
    for r in details["shodan"]:
        service_counts[r["service"]] = service_counts.get(r["service"], 0) + 1

    issuer_counts = {}
    for c in details["certs"]:
        issuer = simplify_issuer(c["issuer"])
        issuer_counts[issuer] = issuer_counts.get(issuer, 0) + 1
    top_issuers = sorted(issuer_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    chart_data = {
        "services": {
            "labels": list(service_counts.keys()),
            "data": list(service_counts.values()),
        },
        "issuers": {
            "labels": [i[0] for i in top_issuers],
            "data": [i[1] for i in top_issuers],
        },
        "trend": {
            "labels": [t["scan_date"][:10] for t in trend],
            "data": [t["subdomain_count"] for t in trend],
        },
    }
    previous_id = get_previous_scan(scan_id, details["target"])
    diff = get_scan_diff(scan_id, previous_id) if previous_id else None

    return render_template("history_detail.html", scan_id=scan_id, details=details, chart_data=chart_data, diff=diff)

# CSV export
@app.route("/export/<int:scan_id>/csv")
def export_csv(scan_id):
    """Export scan results as a CSV file download."""
    details = get_scan_details(scan_id)
    if not details:
        return "Scan not found", 404

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Target", details["target"]])
    writer.writerow(["Scan Date", details["scan_date"]])
    writer.writerow([])

    writer.writerow(["-- WHOIS --"])
    writer.writerow(["Registrar", details["whois"]["registrar"]])
    writer.writerow(["Created", details["whois"]["creation_date"]])
    writer.writerow(["Expires", details["whois"]["expiration_date"]])
    writer.writerow(["Name Servers", details["whois"]["name_servers"]])
    writer.writerow([])

    writer.writerow(["-- Exposed Services (Shodan) --"])
    writer.writerow(["IP", "Port", "Service", "Banner"])
    for r in details["shodan"]:
        writer.writerow([r["ip"], r["port"], r["service"], r["banner"]])
    writer.writerow([])

    writer.writerow(["-- Certificates & Subdomains --"])
    writer.writerow(["Subdomain", "Issuer", "Not Before", "Not After"])
    for c in details["certs"]:
        writer.writerow([c["subdomain"], c["issuer"], c["not_before"], c["not_after"]])
    writer.writerow([])

    writer.writerow(["-- Exposed Emails --"])
    writer.writerow(["Email", "Source"])
    for e in details["emails"]:
        writer.writerow([e["email"], e["source"]])

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename={details['target']}_scan_{scan_id}.csv"
    return response

# PDF export
@app.route("/export/<int:scan_id>/pdf")
def export_pdf(scan_id):
    """Export scan results as a formatted PDF report via ReportLab."""
    details = get_scan_details(scan_id)
    if not details:
        return "Scan not found", 404

    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=letter,
                             topMargin=0.75 * inch, bottomMargin=0.75 * inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=20)
    section_style = ParagraphStyle("SectionStyle", parent=styles["Heading2"],
                                    spaceBefore=14, spaceAfter=6)

    elements = []

    # Title
    elements.append(Paragraph(f"OSINT Report: {details['target']}", title_style))
    elements.append(Paragraph(f"Scan Date: {details['scan_date']}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # WHOIS
    elements.append(Paragraph("WHOIS Information", section_style))
    whois_table = Table([
        ["Registrar", details["whois"]["registrar"]],
        ["Created", details["whois"]["creation_date"]],
        ["Expires", details["whois"]["expiration_date"]],
        ["Name Servers", details["whois"]["name_servers"]],
    ], colWidths=[1.5 * inch, 5 * inch])
    whois_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(whois_table)

    # Shodan
    elements.append(Paragraph("Exposed Services (Shodan)", section_style))
    if details["shodan"]:
        data = [["IP", "Port", "Service", "Banner"]] + [
            [r["ip"], str(r["port"]), r["service"], r["banner"]] for r in details["shodan"]
        ]
        shodan_table = Table(data, colWidths=[1.3 * inch, 0.7 * inch, 1 * inch, 3.5 * inch])
        shodan_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(shodan_table)
    else:
        elements.append(Paragraph("No results found.", styles["Normal"]))

    # Certificates (limit to first 30 for PDF readability)
    elements.append(Paragraph(f"Certificates & Subdomains ({len(details['certs'])} found)", section_style))
    if details["certs"]:
        shown = details["certs"][:30]
        data = [["Subdomain", "Issuer"]] + [
            [c["subdomain"], simplify_issuer(c["issuer"])] for c in shown
        ]
        cert_table = Table(data, colWidths=[3.5 * inch, 3 * inch])
        cert_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(cert_table)
        if len(details["certs"]) > 30:
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(
                f"...and {len(details['certs']) - 30} more (see CSV export for full list).",
                styles["Normal"]
            ))
    else:
        elements.append(Paragraph("No certificate data recorded.", styles["Normal"]))

    # Emails
    elements.append(Paragraph("Exposed Emails", section_style))
    if details["emails"]:
        data = [["Email", "Source"]] + [[e["email"], e["source"]] for e in details["emails"]]
        email_table = Table(data, colWidths=[4 * inch, 2.5 * inch])
        email_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(email_table)
    else:
        elements.append(Paragraph("No exposed emails found.", styles["Normal"]))

    doc.build(elements)
    output.seek(0)

    response = Response(output.getvalue(), mimetype="application/pdf")
    response.headers["Content-Disposition"] = f"attachment; filename={details['target']}_report_{scan_id}.pdf"
    return response

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
