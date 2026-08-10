import ipaddress
import requests


def get_ip_location(ip: str) -> dict:
    """
    Return geolocation information for a public IP address.

    Invalid, private, reserved, or non-global IP addresses
    are returned as Unknown without sending an API request.
    """
    try:
        ip_object = ipaddress.ip_address(ip)

    except ValueError:
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
        }

    if not ip_object.is_global:
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
        }

    url = f"http://ip-api.com/json/{ip}"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") != "success":
            return {
                "ip": ip,
                "country": "Unknown",
                "city": "Unknown",
                "latitude": None,
                "longitude": None,
            }

        return {
            "ip": ip,
            "country": data.get("country"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
        }

    except requests.RequestException:
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
        }