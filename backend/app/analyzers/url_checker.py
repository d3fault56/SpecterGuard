"""
URL Reputation Checker - Phase 2 Feature

Checks URLs against multiple threat intelligence APIs:
- VirusTotal (free tier: 4 requests/min)
- URLhaus (completely free)
"""

import httpx
import os
from typing import Tuple, List
import re
from urllib.parse import urlparse


class URLReputation:
    """Check URL reputation against threat databases."""
    
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/url/"
        self.timeout = 5
    
    def check_url(self, url: str) -> Tuple[bool, str, List[str], float]:
        """
        Check URL reputation.
        
        Returns:
            is_malicious: bool
            verdict: str - "malicious", "suspicious", or "clean"
            detections: List[str]
            confidence: float - 0.0 to 1.0
        """
        
        if not self._is_valid_url(url):
            return False, "invalid_url", ["Invalid URL format"], 0.8
        
        detections = []
        confidence = 0.0
        
        # Check URLhaus (free)
        urlhaus_result = self._check_urlhaus(url)
        if urlhaus_result:
            detections.extend(urlhaus_result)
            confidence += 0.4
        
        # Check VirusTotal (if API key available)
        if self.vt_api_key:
            vt_result = self._check_virustotal(url)
            if vt_result:
                detections.extend(vt_result)
                confidence += 0.4
        
        # Heuristic checks (always run)
        heuristic_result = self._heuristic_checks(url)
        if heuristic_result:
            detections.extend(heuristic_result)
            confidence += 0.2
        
        # Determine verdict
        is_malicious = len(detections) > 0
        if len(detections) >= 2:
            verdict = "malicious"
        elif len(detections) == 1:
            verdict = "suspicious"
        else:
            verdict = "clean"
        
        confidence = min(confidence, 1.0)
        
        return is_malicious, verdict, detections, confidence
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _check_urlhaus(self, url: str) -> List[str]:
        """Check URLhaus abuse.ch database (free)."""
        detections = []
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    self.urlhaus_api,
                    data={"url": url}
                )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    if data.get("result") == "malware":
                        threat_type = data.get("threat", "unknown malware")
                        detections.append(f"URLhaus: Malware ({threat_type})")
                    elif data.get("result") == "phishing":
                        detections.append("URLhaus: Phishing site")
                    elif data.get("result") == "suspicious":
                        detections.append("URLhaus: Suspicious URL")
        
        except Exception as e:
            print(f"URLhaus check failed: {e}")
        
        return detections
    
    def _check_virustotal(self, url: str) -> List[str]:
        """Check VirusTotal (free tier: 4 req/min)."""
        detections = []
        
        if not self.vt_api_key:
            return detections
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                headers = {"x-apikey": self.vt_api_key}
                
                response = client.get(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    params={"filter": f"url:{url}"}
                )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("data"):
                    url_obj = data["data"][0]
                    stats = url_obj.get("attributes", {}).get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    if malicious > 0:
                        detections.append(f"VirusTotal: {malicious} vendors flagged as malicious")
                    elif suspicious > 0:
                        detections.append(f"VirusTotal: {suspicious} vendors flagged as suspicious")
        
        except Exception as e:
            print(f"VirusTotal check failed: {e}")
        
        return detections
    
    def _heuristic_checks(self, url: str) -> List[str]:
        """Local heuristic checks (always fast)."""
        detections = []
        lower_url = url.lower()
        
        # Check for IP address (often phishing)
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", lower_url):
            detections.append("Heuristic: IP address used instead of domain")
        
        # Check for suspicious TLDs
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".top", ".download"]
        if any(lower_url.endswith(tld) for tld in suspicious_tlds):
            detections.append("Heuristic: Suspicious top-level domain")
        
        # Check for URL length (obfuscation indicator)
        if len(url) > 120:
            detections.append("Heuristic: Unusually long URL")
        
        # Check for homograph attacks
        homograph_patterns = [
            (r"amaz0n", "amazon"),
            (r"paypa1", "paypal"),
            (r"appl3", "apple"),
        ]
        for fake, real in homograph_patterns:
            if re.search(fake, lower_url):
                detections.append(f"Heuristic: Possible homograph of {real}")
        
        return detections