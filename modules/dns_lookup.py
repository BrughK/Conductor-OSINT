# DNS record lookup via dnspython.

# Resolves A, AAAA, MX, TXT, NS, and CNAME records for a target domain.
# Handles NoAnswer (empty set), NXDOMAIN (domain doesn't exist), and timeouts.

# Return contract: {"records": {type: [value, ...]}, "error": str|None, "partial_errors": dict|None}

import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]


def get_dns_records(target):
    """Query all DNS record types for the target. Returns grouped by type with error info."""
    results = {}
    errors = {}

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(target, record_type, lifetime=5)
            results[record_type] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except dns.resolver.NXDOMAIN:
            return {"records": {}, "error": f"Domain {target} does not exist"}
        except Exception as e:
            results[record_type] = []
            errors[record_type] = str(e)

    return {"records": results, "error": None, "partial_errors": errors or None}