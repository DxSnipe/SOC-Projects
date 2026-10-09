import os
import urllib.request
import urllib.error


def query_virustotal_ip(ip):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "provider": "VirusTotal",
            "status": "not_configured",
            "observable": ip
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return {
                "provider": "VirusTotal",
                "status": "success",
                "observable": ip,
                "data": response.read().decode("utf-8")
            }

    except urllib.error.HTTPError as error:
        return {
            "provider": "VirusTotal",
            "status": "http_error",
            "observable": ip,
            "code": error.code
        }

    except (urllib.error.URLError, TimeoutError) as error:
        return {
            "provider": "VirusTotal",
            "status": "connection_error",
            "observable": ip,
            "error": str(error)
        }
