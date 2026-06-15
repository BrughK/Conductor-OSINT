# Certificate Transparency log lookup via crt.sh API.

# Returns subdomains, certificate issuers, and validity dates.
# Implements exponential backoff retry (3s, 6s, 9s) to handle API rate limits.

# Return contract: {"certs": [{"subdomain", "issuer", "not_before", "not_after"}], "error": str|None}

import requests
import time

def get_certificates(target, retries=4):
    url = f"https://crt.sh/?q=%.{target}&output=json"

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            seen = set()
            certs = []

            for entry in data:
                subdomain = entry.get("name_value", "").strip()
                for name in subdomain.split("\n"):
                    name = name.strip()
                    if name and name not in seen:
                        seen.add(name)
                        certs.append({
                            "subdomain": name,
                            "issuer": entry.get("issuer_name", "N/A"),
                            "not_before": entry.get("not_before", "N/A"),
                            "not_after": entry.get("not_after", "N/A"),
                        })

            return {"certs": certs, "error": None}

        except Exception as e:
            if attempt < retries - 1:
                time.sleep(3 * (attempt + 1))  # 3s, 6s, 9s backoff
                continue
            return {"certs": [], "error": str(e)}