# Email harvesting from public sources.

# Two sources:
#  1. Website scraping — fetches the target's HTTPS homepage and extracts email addresses via regex
#  2. Certificate fields — parses email addresses from TLS certificate issuer DN strings

# Return contract: {"emails": [{"email", "source"}], "error": str|None}

import re
import requests

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

def get_emails(target, cert_data=None):
    """Harvest emails from website scraping and certificate issuer fields."""
    emails = set()

    scraped = _scrape_website(target)
    for email in scraped:
        emails.add((email, "website"))

    if cert_data:
        for cert in cert_data:
            issuer = cert.get("issuer", "")
            found = EMAIL_REGEX.findall(issuer)
            for email in found:
                emails.add((email, "certificate"))

    results = [{"email": e[0], "source": e[1]} for e in emails]
    return {"emails": results, "error": None}


def _scrape_website(target):
    """Fetch the HTTPS homepage and extract all email addresses."""
    found = set()
    try:
        url = f"https://{target}"
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        found.update(EMAIL_REGEX.findall(response.text))
    except Exception:
        pass

    return found