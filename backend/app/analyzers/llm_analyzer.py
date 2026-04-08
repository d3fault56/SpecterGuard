"""
LLM Analyzer with Few-Shot Examples - Phase 2 Feature

Enhanced Claude prompts with few-shot examples for better accuracy.
"""

from anthropic import Anthropic
from app.config import get_settings
from app.analyzers.base import BaseAnalyzer
from typing import Tuple, List
import json
import re


class LLMAnalyzer(BaseAnalyzer):
    """Claude-based scam analyzer with improved prompting."""
    
    def __init__(self):
        self.settings = get_settings()
        self.client = Anthropic(api_key=self.settings.anthropic_api_key)
    
    def analyze(self, input_type: str, content: str) -> Tuple[str, float, str, List[str]]:
        """Analyze content using Claude with improved prompting."""
        
        prompt = self._build_prompt(input_type, content)
        
        try:
            message = self.client.messages.create(
                model=self.settings.llm_model,
                max_tokens=self.settings.llm_max_tokens,
                temperature=self.settings.llm_temperature,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            )
            
            response_text = message.content[0].text
            return self._parse_response(response_text)
        
        except Exception as e:
            print(f"LLM error: {e}")
            # Fallback to heuristic
            from app.analyzers.heuristic import HeuristicAnalyzer
            fallback = HeuristicAnalyzer()
            return fallback.analyze(input_type, content)
    
    def _build_prompt(self, input_type: str, content: str) -> str:
        """Build analysis prompt with few-shot examples."""
        
        type_hints = {
            "text": "This is a text message or chat.",
            "email": "This is an email message (headers + body).",
            "url": "This is a URL or domain.",
        }
        
        hint = type_hints.get(input_type, "")
        few_shot = self._get_few_shot_examples(input_type)
        
        return f"""
You are an expert scam detector with years of experience identifying phishing, social engineering, and fraud.

{hint}

IMPORTANT: Analyze objectively and focus on concrete indicators, not just urgency or emotion.

{few_shot}

---

**Content to analyze:**
{content}

---

Respond with EXACTLY this JSON structure (no markdown, no preamble):
{{
  "verdict": "likely_scam" | "suspicious" | "safe",
  "confidence": <float 0.0-1.0>,
  "explanation": "<2-3 sentence plain-English explanation>",
  "red_flags": [<list of specific red flags detected, max 5>]
}}

Be concise and objective. Focus on:
1. Concrete indicators (urgency language, credential requests, URL anomalies)
2. Authentication failures (if email)
3. Known phishing patterns
4. Authority impersonation attempts
5. Unusual link/domain behavior

Return ONLY valid JSON, no other text.
"""
    
    def _get_few_shot_examples(self, input_type: str) -> str:
        """Provide few-shot examples for better accuracy."""
        
        if input_type == "text":
            return """EXAMPLES FOR TEXT MESSAGES:

Example 1 (SCAM):
Input: "Verify your Amazon account NOW! Click: bit.ly/amazon-verify Your account will be CLOSED in 24 hours!!!"
Expected Output: {
  "verdict": "likely_scam",
  "confidence": 0.95,
  "explanation": "Multiple red flags: urgency language, shortened URL, account closure threat, and credential request pattern.",
  "red_flags": ["Urgency language", "Shortened URL", "Account closure threat", "Impersonation of Amazon"]
}

Example 2 (SAFE):
Input: "Hi, your package has been delivered. Track it here: https://www.fedex.com/track/123456"
Expected Output: {
  "verdict": "safe",
  "confidence": 0.9,
  "explanation": "Legitimate shipping notification with official tracking URL from recognized shipper.",
  "red_flags": []
}

Example 3 (SUSPICIOUS):
Input: "Your PayPal account has unusual activity. Verify within 24 hours or it will be locked."
Expected Output: {
  "verdict": "suspicious",
  "confidence": 0.65,
  "explanation": "Possible legitimate bank alert, but deadline pressure and vague sender are red flags.",
  "red_flags": ["Time pressure", "Vague sender"]
}"""
        
        elif input_type == "email":
            return """EXAMPLES FOR EMAILS:

Example 1 (SCAM):
Input: "From: paypal-support@paypa1.com\nSubject: URGENT: Verify Your Account\n\nYour account will be closed unless you verify immediately. Enter password: ___"
Expected Output: {
  "verdict": "likely_scam",
  "confidence": 0.98,
  "explanation": "Critical red flags: domain typosquat (paypa1 vs paypal), urgent language, credential request, and likely SPF failure.",
  "red_flags": ["Domain typosquat", "Credential request", "Urgency language", "From address spoofing"]
}

Example 2 (SAFE):
Input: "From: noreply@amazon.com\nSubject: Your Order #12345 Has Shipped\n\nYour package will arrive in 2-3 days."
Expected Output: {
  "verdict": "safe",
  "confidence": 0.95,
  "explanation": "Legitimate order notification from official Amazon domain with no credential requests.",
  "red_flags": []
}"""
        
        elif input_type == "url":
            return """EXAMPLES FOR URLS:

Example 1 (SCAM):
Input: "https://amaz0n-verify.top/account/login"
Expected Output: {
  "verdict": "likely_scam",
  "confidence": 0.92,
  "explanation": "Domain typosquat (0 instead of o) and suspicious TLD (.top). Strong phishing indicator.",
  "red_flags": ["Domain typosquat", "Suspicious TLD (.top)", "Account login URL"]
}

Example 2 (SAFE):
Input: "https://www.google.com"
Expected Output: {
  "verdict": "safe",
  "confidence": 0.99,
  "explanation": "Official Google domain with standard HTTPS.",
  "red_flags": []
}

Example 3 (SUSPICIOUS):
Input: "https://192.168.1.1/verify-paypal"
Expected Output: {
  "verdict": "suspicious",
  "confidence": 0.7,
  "explanation": "IP address instead of domain, and suspicious path. Likely phishing.",
  "red_flags": ["IP address used", "Suspicious path"]
}"""
        
        else:
            return ""
    
    def _parse_response(self, response_text: str) -> Tuple[str, float, str, List[str]]:
        """Parse LLM JSON response."""
        
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if not json_match:
            raise ValueError("No JSON found in response")
        
        try:
            data = json.loads(json_match.group())
            
            return (
                data.get("verdict", "suspicious"),
                float(data.get("confidence", 0.5)),
                data.get("explanation", ""),
                data.get("red_flags", []),
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON: {e}")