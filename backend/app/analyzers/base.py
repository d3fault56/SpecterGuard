from abc import ABC, abstractmethod
from typing import Tuple, List

class BaseAnalyzer(ABC):
    """
    Abstract analyzer interface.
    
    FUTURE: 
    - Expand to support tool invocation (URL checker, email parser)
    - Add reasoning pipeline hooks for multi-step analysis
    - Support context injection from retrieval system
    - Add telemetry for model routing decisions
    """
    
    @abstractmethod
    def analyze(self, input_type: str, content: str) -> Tuple[str, float, str, List[str]]:
        """
        Analyze content for scam indicators.
        
        Returns:
            verdict: "likely_scam", "suspicious", or "safe"
            confidence: 0.0 to 1.0
            explanation: Human-readable reasoning
            red_flags: List of detected warning signs
        """
        pass