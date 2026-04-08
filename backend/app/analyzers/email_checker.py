"""
Email Header Analyzer - Phase 2 Feature

Parses email headers and checks for:
- SPF authentication failures
- DKIM signature problems
- DMARC policy violations
- Reply-To spoofing
"""

from typing import Tuple, List
from email.parser import Parser
from email.message import Message
import re


class EmailHeaderAnalyzer:
    """Analyze email headers for authentication failures and spoofing."""
    
    def analyze(self, email_content: str) -> Tuple[List[str], float]:
        """
        Parse and analyze email headers.
        
        Returns:
            red_flags: List[str] - Detected issues
            confidence_boost: float - How much to boost scam confidence (0.0-0.5)
        """
        flags = []
        confidence_boost = 0.0
        
        try:
            message = self._parse_email(email_content)
            
            # Check authentication results
            auth_flags, auth_boost = self._check_authentication(message)
            flags.extend(auth_flags)
            confidence_boost += auth_boost
            
            # Check for spoofing patterns
            spoof_flags, spoof_boost = self._check_spoofing(message)
            flags.extend(spoof_flags)
            confidence_boost += spoof_boost
            
            # Check header structure
            struct_flags, struct_boost = self._check_header_structure(message)
            flags.extend(struct_flags)
            confidence_boost += struct_boost
        
        except Exception as e:
            print(f"Email header analysis error: {e}")
        
        return flags, min(confidence_boost, 0.5)
    
    def _parse_email(self, email_content: str) -> Message:
        """Parse email content into message object."""
        parser = Parser()
        return parser.parsestr(email_content)
    
    def _check_authentication(self, message: Message) -> Tuple[List[str], float]:
        """Check SPF, DKIM, DMARC results."""
        flags = []
        boost = 0.0
        
        auth_results = message.get("Authentication-Results", "").lower()
        
        if not auth_results:
            flags.append("Email: No authentication headers (missing SPF/DKIM/DMARC)")
            boost += 0.15
        else:
            # Check SPF
            if "spf=fail" in auth_results:
                flags.append("Email: SPF check failed (sender not authorized)")
                boost += 0.2
            elif "spf=softfail" in auth_results:
                flags.append("Email: SPF softfail (sender configuration issue)")
                boost += 0.1
            
            # Check DKIM
            if "dkim=fail" in auth_results:
                flags.append("Email: DKIM signature invalid (email may be forged)")
                boost += 0.2
            
            # Check DMARC
            if "dmarc=fail" in auth_results:
                flags.append("Email: DMARC policy violation (unauthorized sender)")
                boost += 0.25
            elif "dmarc=quarantine" in auth_results:
                flags.append("Email: DMARC quarantine (suspicious email)")
                boost += 0.1
        
        return flags, boost
    
    def _check_spoofing(self, message: Message) -> Tuple[List[str], float]:
        """Check for common spoofing patterns."""
        flags = []
        boost = 0.0
        
        from_addr = message.get("From", "").lower()
        reply_to = message.get("Reply-To", "").lower()
        sender = message.get("Sender", "").lower()
        return_path = message.get("Return-Path", "").lower()
        
        # Extract domains
        from_domain = self._extract_domain(from_addr)
        reply_domain = self._extract_domain(reply_to)
        return_domain = self._extract_domain(return_path)
        
        # Check for mismatch
        if from_addr and reply_to:
            if from_domain and reply_domain and from_domain != reply_domain:
                flags.append(f"Email: Reply-To mismatch ({reply_domain} vs {from_domain})")
                boost += 0.2
        
        if from_addr and return_path:
            if from_domain and return_domain and from_domain != return_domain:
                flags.append(f"Email: Return-Path mismatch ({return_domain} vs {from_domain})")
                boost += 0.15
        
        # Check for impersonation
        major_companies = ["amazon", "paypal", "apple", "google", "microsoft", "bank"]
        for company in major_companies:
            if company in from_domain:
                if f"@{company}.com" not in from_addr and f"@{company}.co.uk" not in from_addr:
                    flags.append(f"Email: Possible {company.title()} impersonation")
                    boost += 0.25
        
        # Check for suspicious sender patterns
        if re.search(r"noreply|no-reply|donotreply", from_addr):
            flags.append("Email: No-reply address (unusual for legitimate requests)")
            boost += 0.1
        
        return flags, boost
    
    def _check_header_structure(self, message: Message) -> Tuple[List[str], float]:
        """Check for malformed headers and suspicious patterns."""
        flags = []
        boost = 0.0
        
        # Check for missing standard headers
        required_headers = ["From", "Subject", "Date"]
        missing = [h for h in required_headers if not message.get(h)]
        if missing:
            flags.append(f"Email: Missing standard headers ({', '.join(missing)})")
            boost += 0.1
        
        # Check for excessive headers
        header_count = len(message.items())
        if header_count > 50:
            flags.append(f"Email: Excessive headers ({header_count}) - possible obfuscation")
            boost += 0.1
        
        # Check for suspicious content-type
        content_type = message.get("Content-Type", "").lower()
        if "multipart/mixed" in content_type and "application" in content_type:
            flags.append("Email: Mixed content with application attachments (executable risk)")
            boost += 0.15
        
        return flags, boost
    
    def _extract_domain(self, email_address: str) -> str:
        """Extract domain from email address."""
        if not email_address:
            return ""
        
        email_address = email_address.strip("<>")
        
        if "@" in email_address:
            return email_address.split("@")[1].lower()
        
        return ""