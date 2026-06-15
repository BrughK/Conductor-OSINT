# WHOIS domain lookup via the python-whois library.

# Handles list-vs-scalar date fields and list name_servers by normalizing to strings.
# Returns N/A for missing fields and str(error) on failure.

# Return contract: {"registrar", "creation_date", "expiration_date", "name_servers", "error": str|None}


import whois

def parse_date(date_field):
    if not date_field:
        return "N/A"
    # sometimes it returns a list of dates, just take the first one
    if isinstance(date_field, list):
        date_field = date_field[0]
    return date_field.strftime("%Y-%m-%d") if hasattr(date_field, 'strftime') else str(date_field)

def get_whois(target):
    try:
        w = whois.whois(target)

        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = ", ".join(name_servers)

        return {
            "registrar": w.registrar or "N/A",
            "creation_date": parse_date(w.creation_date),
            "expiration_date": parse_date(w.expiration_date),
            "name_servers": name_servers or "N/A",
            "error": None
        }

    except Exception as e:
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": None,
            "error": str(e)
        }