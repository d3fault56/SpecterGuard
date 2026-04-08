"""
Scan Service with Multi-Pass Analysis - Phase 2

Orchestrates multiple analyzers and combines their results.
"""

from sqlalchemy.orm import Session
from app.models import ScanRequest, ScanResponse
from app.database import ScanRecord, PhishingPattern
from app.analyzers.llm_analyzer import LLMAnalyzer
from app.analyzers.heuristic import HeuristicAnalyzer
from app.analyzers.url_checker import URLReputation
from app.analyzers.email_checker import EmailHeaderAnalyzer
from typing import List, Tuple, Dict, Any
import json


class ScanService:
    """Orchestrates analysis pipeline with multiple analyzers."""
    
    def __init__(self):
        self.llm_analyzer = LLMAnalyzer()
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.url_checker = URLReputation()
        self.email_analyzer = EmailHeaderAnalyzer()
    
    def scan(self, request: ScanRequest, db: Session) -> ScanResponse:
        """Run multi-pass analysis and store result."""
        
        results = []
        
        # 1. Heuristic analyzer
        try:
            h_verdict, h_conf, h_explain, h_flags = self.heuristic_analyzer.analyze(
                request.input_type, request.content
            )
            results.append({
                "source": "heuristic",
                "verdict": h_verdict,
                "confidence": h_conf,
                "flags": h_flags,
            })
        except Exception as e:
            print(f"Heuristic analyzer error: {e}")
        
        # 2. Pattern database check
        try:
            p_verdict, p_conf, p_flags = self._check_pattern_database(
                request.content, db
            )
            if p_flags:
                results.append({
                    "source": "pattern_db",
                    "verdict": p_verdict,
                    "confidence": p_conf,
                    "flags": p_flags,
                })
        except Exception as e:
            print(f"Pattern database error: {e}")
        
        # 3. URL reputation check (if URL input)
        if request.input_type == "url":
            try:
                is_malicious, verdict, detections, url_conf = self.url_checker.check_url(
                    request.content
                )
                if detections:
                    results.append({
                        "source": "url_reputation",
                        "verdict": "likely_scam" if is_malicious else "safe",
                        "confidence": url_conf,
                        "flags": detections,
                    })
            except Exception as e:
                print(f"URL reputation check error: {e}")
        
        # 4. Email header check (if email input)
        if request.input_type == "email":
            try:
                email_flags, email_conf = self.email_analyzer.analyze(request.content)
                if email_flags:
                    results.append({
                        "source": "email_headers",
                        "verdict": "suspicious" if email_conf > 0.1 else "safe",
                        "confidence": email_conf,
                        "flags": email_flags,
                    })
            except Exception as e:
                print(f"Email header analysis error: {e}")
        
        # 5. LLM analyzer
        try:
            llm_verdict, llm_conf, llm_explain, llm_flags = self.llm_analyzer.analyze(
                request.input_type, request.content
            )
            results.append({
                "source": "llm",
                "verdict": llm_verdict,
                "confidence": llm_conf,
                "flags": llm_flags,
                "explanation": llm_explain,
            })
        except Exception as e:
            print(f"LLM analyzer error: {e}")
        
        # Combine results
        final_verdict, final_conf, final_explain, final_flags, analyzers_used = (
            self._combine_results(results)
        )
        
        # Store in database
        record = ScanRecord(
            input_type=request.input_type,
            input_content=request.content,
            verdict=final_verdict,
            confidence=final_conf,
            explanation=final_explain,
            red_flags=json.dumps(list(set(final_flags))),
            analyzer_used=analyzers_used,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        
        return ScanResponse(
            id=record.id,
            verdict=final_verdict,
            confidence=final_conf,
            explanation=final_explain,
            red_flags=list(set(final_flags)),
            analyzer_used=analyzers_used,
            created_at=record.created_at,
        )
    
    def _check_pattern_database(self, content: str, db: Session) -> Tuple[str, float, List[str]]:
        """Check content against phishing pattern database."""
        
        flags = []
        score = 0.0
        
        patterns = db.query(PhishingPattern).all()
        
        for pattern in patterns:
            if pattern.pattern.lower() in content.lower():
                flags.append(f"Known pattern: {pattern.description}")
                score += pattern.confidence_boost
        
        if score >= 0.3:
            verdict = "suspicious"
        else:
            verdict = "safe"
        
        return verdict, min(score, 1.0), flags
    
    def _combine_results(self, results: List[Dict[str, Any]]) -> Tuple[str, float, str, List[str], str]:
        """Combine results from multiple analyzers using weighted scoring."""
        
        weights = {
            "heuristic": 0.1,
            "pattern_db": 0.15,
            "url_reputation": 0.2,
            "email_headers": 0.15,
            "llm": 0.4,
        }
        
        verdict_scores = {
            "likely_scam": 1.0,
            "suspicious": 0.5,
            "safe": 0.0,
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        all_flags = []
        llm_explanation = ""
        analyzers_used = []
        
        for result in results:
            source = result["source"]
            weight = weights.get(source, 0.0)
            
            verdict = result.get("verdict", "safe")
            verdict_score = verdict_scores.get(verdict, 0.5)
            
            weighted_score += verdict_score * weight
            total_weight += weight
            
            all_flags.extend(result.get("flags", []))
            
            if source == "llm":
                llm_explanation = result.get("explanation", "Multi-analyzer analysis")
            
            analyzers_used.append(source)
        
        if total_weight > 0:
            final_confidence = weighted_score / total_weight
        else:
            final_confidence = 0.5
        
        if final_confidence >= 0.7:
            final_verdict = "likely_scam"
        elif final_confidence >= 0.4:
            final_verdict = "suspicious"
        else:
            final_verdict = "safe"
        
        if llm_explanation:
            final_explanation = llm_explanation
        else:
            flag_count = len(set(all_flags))
            if final_verdict == "likely_scam":
                final_explanation = f"Multiple indicators detected ({flag_count} red flags). This appears to be a scam attempt."
            elif final_verdict == "suspicious":
                final_explanation = f"Some warning signs found ({flag_count} red flags). Exercise caution and verify the sender."
            else:
                final_explanation = "No obvious scam indicators detected, but always verify requests for sensitive info."
        
        unique_flags = list(set(all_flags))
        
        return (
            final_verdict,
            min(final_confidence, 1.0),
            final_explanation,
            unique_flags,
            "multi-pass"
        )
    
    def get_history(self, db: Session, limit: int = 50) -> tuple[List[ScanResponse], int]:
        """Fetch scan history."""
        
        records = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit).all()
        total = db.query(ScanRecord).count()
        
        responses = [
            ScanResponse(
                id=r.id,
                verdict=r.verdict,
                confidence=r.confidence,
                explanation=r.explanation,
                red_flags=json.loads(r.red_flags) if r.red_flags else [],
                analyzer_used=r.analyzer_used,
                created_at=r.created_at,
            )
            for r in records
        ]
        
        return responses, total