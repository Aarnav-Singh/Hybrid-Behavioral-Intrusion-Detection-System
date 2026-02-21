import os
import httpx
import logging
import asyncio
from typing import Dict, Any, Optional

logger = logging.getLogger("threat_intel")

class ThreatIntelligenceAPI:
    """
    A unified Threat Intelligence Client for enriching IDS alerts.
    Supports either a Fortinet commercial API (FortiGuard) or a free fallback like AbuseIPDB.
    """
    
    def __init__(self, provider: str = "abuseipdb"):
        self.provider = provider.lower()
        self.client = httpx.AsyncClient(timeout=5.0)
        
        # In a real environment, load these from your .env file
        self.api_key = os.getenv(f"{provider.upper()}_API_KEY", "")
        
        # Simple local cache to prevent hitting API rate limits for repeated IPs
        # Format: { "1.2.3.4": {"score": 85, "malicious": True} }
        self._cache: Dict[str, Dict[str, Any]] = {}
        
        if not self.api_key:
            logger.warning(f"{provider.title()} API key not found in environment variables. Threat Intel is disabled.")

    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Check an IP address against the configured Threat Intelligence provider.
        Returns a normalized dictionary of threat data, or None if the check failed/is disabled.
        """
        if not self.api_key:
            return None
            
        # Check cache first (cache TTL logic omitted for brevity)
        if ip_address in self._cache:
            logger.debug(f"Cache hit for IP: {ip_address}")
            return self._cache[ip_address]
            
        logger.info(f"Querying {self.provider.title()} for IP: {ip_address}")
        
        try:
            if self.provider == "fortiguard":
                result = await self._query_fortiguard(ip_address)
            elif self.provider == "abuseipdb":
                result = await self._query_abuseipdb(ip_address)
            else:
                logger.error(f"Unsupported threat intel provider: {self.provider}")
                return None
                
            # Store in cache
            if result:
                self._cache[ip_address] = result
                
            return result
            
        except httpx.HTTPError as e:
            logger.error(f"HTTP error connecting to {self.provider}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in Threat Intel lookup: {str(e)}")
            return None

    async def _query_fortiguard(self, ip: str) -> Dict[str, Any]:
        """
        Example integration with FortiGuard Threat Intelligence REST API.
        Requires Fortinet Developer Network (FNDN) access or a private label contract.
        """
        # Note: This is a conceptual endpoint. The actual Fortinet endpoint depends
        # on which specific API product you are subscribed to (e.g., FortiSandbox API, IOC API).
        url = f"https://api.fortinet.com/v1/threat/ip/{ip}"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json"
        }
        
        response = await self.client.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Normalize the vendor-specific data into a standard format for your IDS
        return {
            "source": "FortiGuard",
            "ip": ip,
            "malicious": data.get("risk_score", 0) > 75,
            "confidence": data.get("confidence", 0),
            "tags": data.get("categories", []),
            "raw_score": data.get("risk_score", 0)
        }

    async def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """
        Integration with AbuseIPDB - a great free alternative for portfolio projects.
        Checks if the IP has been reported for abusive behavior (SSH brute force, DDoS, etc).
        """
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "30",
            "verbose": ""
        }
        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        
        response = await self.client.get(url, params=params, headers=headers)
        response.raise_for_status()
        
        data = response.json()["data"]
        
        # Normalize the vendor-specific data
        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "malicious": data.get("abuseConfidenceScore", 0) > 50,
            "confidence": data.get("abuseConfidenceScore", 0),
            "tags": [data.get("domain", "Unknown"), data.get("isp", "Unknown")],
            "raw_score": data.get("abuseConfidenceScore", 0)
        }

    async def close(self):
        """Clean up the HTTP client resources."""
        await self.client.aclose()


# ==========================================
# HOW TO USE THIS IN YOUR FASTAPI BACKEND
# ==========================================
async def example_usage():
    # 1. Initialize the client (usually done once at app startup)
    # Set the ABUSEIPDB_API_KEY environment variable to test this!
    intel_client = ThreatIntelligenceAPI(provider="abuseipdb")
    
    # 2. Inside your detection loop or API route:
    suspicious_ip = "185.153.199.117" # A known bad IP for testing
    
    print(f"Checking {suspicious_ip}...")
    intel_data = await intel_client.check_ip(suspicious_ip)
    
    if intel_data:
        print("Threat Intel Results:")
        print(f"  - Malicious: {intel_data['malicious']}")
        print(f"  - Confidence Score: {intel_data['confidence']}")
        print(f"  - Associated Tags: {intel_data['tags']}")
        
        # 3. Use this data to heavily weight your local anomaly score
        local_anomaly_score = 0.45 # e.g., output from your Random Forest model
        
        if intel_data['malicious']:
            print("\n[!] CRITICAL: Local anomaly matched with global Threat Intel!")
            final_threat_score = min(local_anomaly_score + (intel_data['confidence'] / 100), 1.0)
            print(f"  - Adjusted Threat Score: {final_threat_score:.3f}")
    
    await intel_client.close()

if __name__ == "__main__":
    asyncio.run(example_usage())
