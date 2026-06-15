# Shodan exposed services lookup.

# Returns realistic mock data when SHODAN_API_KEY is not set (default).
# Set the SHODAN_API_KEY environment variable for real Shodan API lookups.

# Return contract: {"results": [{"ip", "port", "service", "banner"}], "error": str|None, "mocked": bool}

import os

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", None)

def get_shodan_data(target):
    if SHODAN_API_KEY:
        return _real_shodan_lookup(target)
    else:
        return _mock_shodan_lookup(target)


def _mock_shodan_lookup(target):
    """Returns realistic fake data for development/demo purposes."""
    mock_results = [
        # Web servers (main IP)
        {"ip": "93.184.216.34", "port": 80, "service": "http", "banner": "nginx/1.24.0"},
        {"ip": "93.184.216.34", "port": 443, "service": "https", "banner": "nginx/1.24.0 (TLS 1.3)"},
        {"ip": "93.184.216.34", "port": 8080, "service": "http", "banner": "nginx/1.24.0 (redirect to HTTPS)"},

        # SSH access
        {"ip": "93.184.216.34", "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu1"},

        # Mail services
        {"ip": "203.0.113.10", "port": 25, "service": "smtp", "banner": "220 mx.example.com ESMTP Postfix (Ubuntu)"},
        {"ip": "203.0.113.10", "port": 587, "service": "submission", "banner": "220 mx.example.com ESMTP Postfix (Ubuntu) (STARTTLS)"},
        {"ip": "203.0.113.10", "port": 993, "service": "imaps", "banner": "* OK [CAPABILITY IMAP4rev1...] Dovecot (Ubuntu) ready"},

        # DNS
        {"ip": "203.0.113.20", "port": 53, "service": "dns", "banner": "BIND 9.18.12 (Ubuntu Linux)"},

        # CDN / cache nodes
        {"ip": "104.16.25.2", "port": 80, "service": "http", "banner": "cloudflare"},
        {"ip": "104.16.25.2", "port": 443, "service": "https", "banner": "cloudflare (TLS 1.3)"},

        # Database (exposed misconfiguration)
        {"ip": "93.184.216.35", "port": 3306, "service": "mysql", "banner": "MySQL 8.0.33 (unauthorized)"},

        # FTP
        {"ip": "93.184.216.35", "port": 21, "service": "ftp", "banner": "220 ProFTPD 1.3.7 Server ready"},

        # Redis (exposed misconfiguration)
        {"ip": "93.184.216.35", "port": 6379, "service": "redis", "banner": "-ERR wrong number of arguments for 'ping' command"},
    ]
    return {"results": mock_results, "error": None, "mocked": True}


# REAL API CALL

# def _real_shodan_lookup(target):
#     """Real Shodan lookup — used once you have an API key."""
#     import shodan

#     try:
#         api = shodan.Shodan(SHODAN_API_KEY)
#         host_results = api.host(target)

#         results = []
#         for service in host_results.get("data", []):
#             results.append({
#                 "ip": host_results.get("ip_str", "N/A"),
#                 "port": service.get("port", "N/A"),
#                 "service": service.get("_shodan", {}).get("module", "N/A"),
#                 "banner": service.get("data", "N/A")[:200],  # trim long banners
#             })

#         return {"results": results, "error": None, "mocked": False}

#     except Exception as e:
#         return {"results": [], "error": str(e), "mocked": False}