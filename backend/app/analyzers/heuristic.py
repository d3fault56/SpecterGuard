from app.analyzers.base import BaseAnalyzer
from typing import Tuple, List
import re

class HeuristicAnalyzer(BaseAnalyzer):
    """
    Rule-based fallback analyzer for when LLM is unavailable.
    
    FUTURE:
    - Expand rule library (learning from scan history)
    - Support domain reputation checks (local DB or API)
    - Add email header parsing (SPF, DKIM, DMARC)
    - Integrate with phishing pattern database
    """
    
    def analyze(self, input_type: str, content: str) -> Tuple[str, float, str, List[str]]:
        """Rule-based analysis."""
        
        red_flags = []
        base_score = 0.0
        
        # Text/email analysis
        if input_type in ["text", "email"]:
            red_flags, base_score = self._analyze_text(content)
        
        # URL analysis
        elif input_type == "url":
            red_flags, base_score = self._analyze_url(content)
        
        # Determine verdict
        if base_score >= 0.7:
            verdict = "likely_scam"
        elif base_score >= 0.4:
            verdict = "suspicious"
        else:
            verdict = "safe"
        
        explanation = self._build_explanation(verdict, len(red_flags))
        
        return verdict, base_score, explanation, red_flags
    
    def _analyze_text(self, content: str) -> Tuple[List[str], float]:
        """Analyze text/email for scam patterns."""
        
        flags = []
        score = 0.0
        
        lower = content.lower()
        
        # Urgency patterns
        urgency_patterns = [
            r"urgent\s(?:action|response|verification)",
            r"act\s+now", r"click\s+immediately",
            r"verify\s+now", r"confirm\s+(?:account|identity)",
            r"(?:your|account)\s+(?:will\s+be\s+)?closed",
        ]
        if any(re.search(p, lower) for p in urgency_patterns):
            flags.append("Urgency language detected")
            score += 0.25
        
        # Financial requests
        if re.search(r"(?:wire|transfer|payment|card|bank|crypto)", lower):
            flags.append("Financial information requested")
            score += 0.2
        
        # Suspicious links
        if re.search(r"https?://", content):
            if re.search(r"bit\.ly|tinyurl|short\.link", lower):
                flags.append("Shortened URL detected")
                score += 0.15
        
        # Misspellings / poor grammar
        if re.search(r"\b(?:ur|u\s|4u|pls)\b", lower):
            flags.append("Casual/misspelled language")
            score += 0.1
        
        # Impersonation
        if re.search(r"(?:from|verify)\s+(?:apple|amazon|paypal|google|bank)", lower, re.IGNORECASE):
            flags.append("Possible impersonation of known company")
            score += 0.25
        
        # Credential requests
        if re.search(r"(?:password|pin|cvv|ssn|social\s+security)", lower):
            flags.append("Credential request detected")
            score += 0.3
        
        return flags, min(score, 1.0)
    
    def _analyze_url(self, url: str) -> Tuple[List[str], float]:
        """Analyze URL for scam indicators."""
        
        flags = []
        score = 0.0
        
        lower = url.lower()
        
        # Suspicious TLDs
        if re.search(r"\.(tk|ml|ga|cf|top|download)$", lower):
            flags.append("Suspicious top-level domain")
            score += 0.2
        
        # IP address instead of domain
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", lower):
            flags.append("IP address used instead of domain")
            score += 0.25
        
        # Domain typosquatting (basic check)
        legit_domains = ["amazon", "apple", "google", "paypal", "facebook", "microsoft"]
        if any(f in lower for f in legit_domains):
            if not any(f"://{domain}" in lower for domain in legit_domains):
                flags.append("Possible domain typosquatting")
                score += 0.2
        
        # Very long URL
        if len(url) > 100:
            flags.append("Unusually long URL")
            score += 0.1
        
        return flags, min(score, 1.0)
    
    def _build_explanation(self, verdict: str, flag_count: int) -> str:
        """Build human-readable explanation."""
        
        if verdict == "likely_scam":
            return f"Multiple red flags detected ({flag_count}). This appears to be a scam attempt."
        elif verdict == "suspicious":
            return f"Some warning signs found ({flag_count}). Exercise caution and verify the sender."
        else:
            return "No obvious scam indicators detected, but always verify requests for sensitive info."