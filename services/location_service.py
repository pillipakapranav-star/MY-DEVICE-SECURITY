"""Network-based location estimate. IP geolocation is approximate, never GPS."""

import datetime
import json
import urllib.request
from config import LOCATION_CACHE_FILE


class LocationService:
    """Return a clearly-labelled network estimate or an unavailable result.

    This project does not access a GPS receiver or Windows location provider.
    IP-based coordinates can be many kilometres away from the device.
    """

    @staticmethod
    def get_current_location() -> dict:
        request = urllib.request.Request(
            "https://ipapi.co/json/",
            headers={"User-Agent": "AegisSentinel/2.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
            lat = float(data["latitude"])
            lon = float(data["longitude"])
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                raise ValueError("Coordinates outside valid range")
            location = {
                "lat": lat,
                "lon": lon,
                "city": data.get("city") or "Unknown",
                "region": data.get("region") or "Unknown",
                "country": data.get("country_name") or data.get("country_code") or "Unknown",
                "postal": data.get("postal") or "Unknown",
                "ip": data.get("ip") or "Unknown",
                "isp": data.get("org") or "Unknown",
                "source": "IP network lookup (ipapi.co)",
                "accuracy": "Approximate; not GPS or device-precise",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                "status": "APPROXIMATE_NETWORK_LOCATION",
            }
            try:
                LOCATION_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                LOCATION_CACHE_FILE.write_text(json.dumps(location, indent=2), encoding="utf-8")
            except OSError:
                pass
            return location
        except Exception as exc:
            return {
                "lat": None,
                "lon": None,
                "city": "Unavailable",
                "region": "Unavailable",
                "country": "Unavailable",
                "postal": "Unavailable",
                "ip": "Unavailable",
                "isp": "Unavailable",
                "source": "None",
                "accuracy": "No location provider succeeded",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "maps_url": "",
                "status": "UNAVAILABLE",
                "error": str(exc),
            }

    @staticmethod
    def get_cached_location() -> dict:
        """Read the last network estimate, explicitly marked as old data."""
        try:
            data = json.loads(LOCATION_CACHE_FILE.read_text(encoding="utf-8"))
            data["status"] = "STALE_CACHED_NETWORK_ESTIMATE"
            data["accuracy"] = "Old approximate IP estimate; not the device's current location"
            return data
        except (OSError, json.JSONDecodeError):
            return LocationService.get_current_location()

    @staticmethod
    def format_sms_text(location: dict, alert_type: str = "FAILED PASSWORD BREACH") -> str:
        lat, lon = location.get("lat"), location.get("lon")
        if lat is None or lon is None:
            coords = "Unavailable"
            maps = "No map link"
        else:
            coords = f"{lat:.4f},{lon:.4f} (approximate IP estimate)"
            maps = location.get("maps_url") or "No map link"
        return (
            f"[AEGIS ALERT] {alert_type}!\n"
            f"Network area: {location.get('city', 'Unknown')}, {location.get('region', '')}\n"
            f"Location: {coords}\nMap: {maps}\n"
            "This is not GPS-accurate."
        )
