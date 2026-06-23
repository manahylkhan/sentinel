import asyncio

import httpx


async def check_abuseipdb(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"source": "abuseipdb", "error": "No API key configured", "flagged": False}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            return {
                "source": "abuseipdb",
                "score": score,
                "country": d.get("countryCode", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "reports": d.get("totalReports", 0),
                "flagged": score > 25,
            }
    except Exception as e:
        return {"source": "abuseipdb", "error": str(e), "flagged": False}


async def check_virustotal(indicator: str, ind_type: str, api_key: str) -> dict:
    if not api_key:
        return {"source": "virustotal", "error": "No API key configured", "flagged": False}
    try:
        endpoints = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "hash": f"https://www.virustotal.com/api/v3/files/{indicator}",
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            if ind_type == "url":
                import base64
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:
                url = endpoints.get(ind_type, endpoints["ip"])

            r = await client.get(url, headers={"x-apikey": api_key})
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values()) if stats else 0
            return {
                "source": "virustotal",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "engines_total": total,
                "flagged": malicious > 0 or suspicious > 2,
            }
    except Exception as e:
        return {"source": "virustotal", "error": str(e), "flagged": False}


async def check_otx(indicator: str, ind_type: str, api_key: str) -> dict:
    if not api_key:
        return {"source": "otx", "error": "No API key configured", "flagged": False}
    type_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file", "email": "domain"}
    otx_type = type_map.get(ind_type, "IPv4")
    # For email, check domain part
    target = indicator.split("@")[-1] if ind_type == "email" else indicator
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{target}/general",
                headers={"X-OTX-API-KEY": api_key},
            )
            data = r.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "source": "otx",
                "pulse_count": pulse_count,
                "threat_score": min(pulse_count * 10, 100),
                "flagged": pulse_count > 0,
            }
    except Exception as e:
        return {"source": "otx", "error": str(e), "flagged": False}


async def check_threatfox(indicator: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": indicator},
            )
            data = r.json()
            found = data.get("query_status") == "ok" and bool(data.get("data"))
            malware = None
            if found and data.get("data"):
                malware = data["data"][0].get("malware_printable")
            return {"source": "threatfox", "found": found, "malware": malware, "flagged": found}
    except Exception as e:
        return {"source": "threatfox", "error": str(e), "flagged": False}


async def check_ipinfo(ip: str, api_key: str) -> dict:
    try:
        url = f"https://ipinfo.io/{ip}/json"
        params = {"token": api_key} if api_key else {}
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, params=params)
            data = r.json()
            org = data.get("org", "")
            is_vpn = "vpn" in org.lower() or "tor" in org.lower()
            is_tor = "tor" in org.lower()
            return {
                "source": "ipinfo",
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "org": org,
                "asn": org.split(" ")[0] if org else "Unknown",
                "is_vpn": is_vpn,
                "is_tor": is_tor,
                "flagged": False,
            }
    except Exception as e:
        return {"source": "ipinfo", "error": str(e), "flagged": False}


async def check_urlhaus(indicator: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": indicator},
            )
            data = r.json()
            found = data.get("query_status") == "is_host" and data.get("urls")
            urls_count = len(data.get("urls", []))
            return {"source": "urlhaus", "found": found, "urls_count": urls_count, "flagged": found}
    except Exception as e:
        return {"source": "urlhaus", "error": str(e), "flagged": False}


async def check_malwarebazaar(hash_value: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": hash_value},
            )
            data = r.json()
            found = data.get("query_status") == "ok" and bool(data.get("data"))
            malware_name = None
            if found and data.get("data"):
                malware_name = data["data"][0].get("signature")
            return {
                "source": "malwarebazaar",
                "found": found,
                "malware_name": malware_name,
                "flagged": found,
            }
    except Exception as e:
        return {"source": "malwarebazaar", "error": str(e), "flagged": False}


async def check_all_feeds(indicator: str, ind_type: str, config) -> dict:
    """Run all relevant feeds in parallel using asyncio.gather."""
    tasks = []
    task_names = []

    if ind_type == "ip":
        tasks = [
            check_abuseipdb(indicator, config.ABUSEIPDB_API_KEY),
            check_virustotal(indicator, ind_type, config.VIRUSTOTAL_API_KEY),
            check_otx(indicator, ind_type, config.OTX_API_KEY),
            check_threatfox(indicator),
            check_ipinfo(indicator, config.IPINFO_API_KEY),
        ]
        task_names = ["abuseipdb", "virustotal", "otx", "threatfox", "ipinfo"]

    elif ind_type == "domain":
        tasks = [
            check_virustotal(indicator, ind_type, config.VIRUSTOTAL_API_KEY),
            check_otx(indicator, ind_type, config.OTX_API_KEY),
            check_threatfox(indicator),
            check_urlhaus(indicator),
        ]
        task_names = ["virustotal", "otx", "threatfox", "urlhaus"]

    elif ind_type == "url":
        tasks = [
            check_virustotal(indicator, ind_type, config.VIRUSTOTAL_API_KEY),
            check_urlhaus(indicator),
            check_threatfox(indicator),
        ]
        task_names = ["virustotal", "urlhaus", "threatfox"]

    elif ind_type == "hash":
        tasks = [
            check_virustotal(indicator, ind_type, config.VIRUSTOTAL_API_KEY),
            check_malwarebazaar(indicator),
            check_otx(indicator, ind_type, config.OTX_API_KEY),
            check_threatfox(indicator),
        ]
        task_names = ["virustotal", "malwarebazaar", "otx", "threatfox"]

    elif ind_type == "email":
        domain = indicator.split("@")[-1]
        tasks = [
            check_virustotal(domain, "domain", config.VIRUSTOTAL_API_KEY),
            check_urlhaus(domain),
            check_otx(indicator, ind_type, config.OTX_API_KEY),
            check_threatfox(indicator),
        ]
        task_names = ["virustotal", "urlhaus", "otx", "threatfox"]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    feed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            feed_results.append({"source": task_names[i], "error": str(result), "flagged": False})
        else:
            feed_results.append(result)

    flagged_by = [r["source"] for r in feed_results if r.get("flagged")]

    return {
        "indicator": indicator,
        "indicator_type": ind_type,
        "feed_results": feed_results,
        "flagged_by": flagged_by,
        "total_feeds_checked": len(feed_results),
    }
