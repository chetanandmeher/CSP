"""
Stitch AI Integration Service
Connects to Stitch AI for intelligent threat analysis and insights
"""

import os
import json
import httpx
from typing import Optional, Dict, Any, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class StitchAIClient:
    """Client for interacting with Stitch AI API"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "claude-3-5-sonnet"
    ):
        """
        Initialize Stitch AI client
        
        Args:
            api_key: Stitch AI API key (defaults to STITCH_AI_API_KEY env var)
            base_url: Stitch AI base URL (defaults to STITCH_AI_BASE_URL env var)
            model: Model to use for analysis
        """
        self.api_key = api_key or os.getenv("STITCH_AI_API_KEY")
        self.base_url = base_url or os.getenv("STITCH_AI_BASE_URL", "https://api.stitch.ai/v1")
        self.model = model
        
        if not self.api_key:
            logger.warning("STITCH_AI_API_KEY not set. Stitch AI features will be limited.")
            
    async def analyze_threat_actor(
        self,
        actor_data: Dict[str, Any],
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze threat actor using Stitch AI
        
        Args:
            actor_data: Threat actor information
            context: Additional context for analysis
            
        Returns:
            Analysis results from Stitch AI
        """
        prompt = self._build_threat_actor_prompt(actor_data, context)
        
        return await self._call_stitch_ai(prompt, "threat_analysis")
        
    async def analyze_attack_pattern(
        self,
        technique_data: Dict[str, Any],
        actor_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze attack pattern/technique using Stitch AI
        
        Args:
            technique_data: Attack technique information
            actor_data: Associated threat actor data
            
        Returns:
            Analysis results
        """
        prompt = self._build_attack_pattern_prompt(technique_data, actor_data)
        
        return await self._call_stitch_ai(prompt, "technique_analysis")
        
    async def generate_threat_report(
        self,
        attackers: List[Dict[str, Any]],
        time_period: str = "24h"
    ) -> Dict[str, Any]:
        """
        Generate comprehensive threat report using Stitch AI
        
        Args:
            attackers: List of attacker data
            time_period: Time period for report
            
        Returns:
            Generated threat report
        """
        prompt = self._build_threat_report_prompt(attackers, time_period)
        
        return await self._call_stitch_ai(prompt, "threat_report")
        
    async def correlate_indicators(
        self,
        indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate security indicators using Stitch AI
        
        Args:
            indicators: List of security indicators
            
        Returns:
            Correlation analysis
        """
        prompt = self._build_correlation_prompt(indicators)
        
        return await self._call_stitch_ai(prompt, "correlation")
        
    async def predict_next_actions(
        self,
        actor_data: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Predict likely next actions of threat actor
        
        Args:
            actor_data: Current threat actor data
            historical_data: Historical attack data
            
        Returns:
            Predictions and recommendations
        """
        prompt = self._build_prediction_prompt(actor_data, historical_data)
        
        return await self._call_stitch_ai(prompt, "prediction")
        
    def _build_threat_actor_prompt(
        self,
        actor_data: Dict[str, Any],
        context: Optional[str] = None
    ) -> str:
        """Build prompt for threat actor analysis"""
        
        prompt = f"""
Analyze the following threat actor data and provide insights:

Threat Actor Information:
{json.dumps(actor_data, indent=2)}

Please provide:
1. Risk Assessment: Overall threat level and justification
2. Attack Patterns: Common techniques and tactics used
3. Targets: Likely target sectors and organizations
4. Capabilities: Technical capabilities and sophistication level
5. Attribution: Possible attribution or group associations
6. Recommendations: Defensive measures and monitoring strategies

{f'Additional Context: {context}' if context else ''}

Format your response as structured JSON with these sections.
"""
        return prompt
        
    def _build_attack_pattern_prompt(
        self,
        technique_data: Dict[str, Any],
        actor_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build prompt for attack pattern analysis"""
        
        prompt = f"""
Analyze the following attack technique/pattern:

Technique Information:
{json.dumps(technique_data, indent=2)}

{f'Associated Threat Actor: {json.dumps(actor_data, indent=2)}' if actor_data else ''}

Please provide:
1. Technique Overview: What this technique does and how it works
2. Detection Methods: How to detect this technique
3. Mitigation Strategies: How to prevent or mitigate this technique
4. Real-World Examples: Known campaigns using this technique
5. Indicators of Compromise: IOCs to look for
6. Tools Used: Common tools for executing this technique

Format your response as structured JSON.
"""
        return prompt
        
    def _build_threat_report_prompt(
        self,
        attackers: List[Dict[str, Any]],
        time_period: str
    ) -> str:
        """Build prompt for threat report generation"""
        
        prompt = f"""
Generate a comprehensive threat intelligence report for the following data:

Time Period: {time_period}
Number of Attackers: {len(attackers)}

Attacker Data:
{json.dumps(attackers[:5], indent=2)}  # Top 5 attackers

Please generate a report including:
1. Executive Summary: High-level overview of threats
2. Key Findings: Most important discoveries
3. Threat Landscape: Overview of active threats
4. Top Threat Actors: Most dangerous actors and their activities
5. Attack Trends: Patterns and trends observed
6. Recommendations: Strategic recommendations for defense
7. Metrics: Key metrics and statistics

Format as a professional threat report in JSON.
"""
        return prompt
        
    def _build_correlation_prompt(
        self,
        indicators: List[Dict[str, Any]]
    ) -> str:
        """Build prompt for indicator correlation"""
        
        prompt = f"""
Correlate the following security indicators and identify relationships:

Indicators:
{json.dumps(indicators, indent=2)}

Please provide:
1. Correlations: Identified relationships between indicators
2. Threat Clusters: Groupings of related indicators
3. Attack Chains: Potential attack sequences
4. Confidence Levels: Confidence in each correlation
5. Recommendations: Actions based on correlations

Format as structured JSON.
"""
        return prompt
        
    def _build_prediction_prompt(
        self,
        actor_data: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> str:
        """Build prompt for attack prediction"""
        
        prompt = f"""
Based on the following threat actor data and historical patterns, predict likely next actions:

Current Threat Actor:
{json.dumps(actor_data, indent=2)}

Historical Attack Data (last 10 attacks):
{json.dumps(historical_data[:10], indent=2)}

Please provide:
1. Predicted Targets: Likely next targets
2. Predicted Techniques: Likely techniques to be used
3. Timeline: Estimated timeframe for next attack
4. Confidence: Confidence level in predictions
5. Indicators to Monitor: What to watch for
6. Defensive Measures: Recommended preparations

Format as structured JSON.
"""
        return prompt
        
    async def _call_stitch_ai(
        self,
        prompt: str,
        analysis_type: str
    ) -> Dict[str, Any]:
        """
        Call Stitch AI API
        
        Args:
            prompt: Analysis prompt
            analysis_type: Type of analysis being performed
            
        Returns:
            Analysis results
        """
        if not self.api_key:
            logger.error("Stitch AI API key not configured")
            return {
                "error": "Stitch AI not configured",
                "analysis_type": analysis_type
            }
            
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/messages",
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "max_tokens": 2048,
                        "messages": [
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ]
                    },
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Extract the text content
                    content = result.get("content", [{}])[0].get("text", "")
                    
                    # Try to parse as JSON
                    try:
                        analysis = json.loads(content)
                    except json.JSONDecodeError:
                        analysis = {"raw_analysis": content}
                        
                    return {
                        "success": True,
                        "analysis_type": analysis_type,
                        "timestamp": datetime.utcnow().isoformat(),
                        "analysis": analysis
                    }
                else:
                    logger.error(f"Stitch AI API error: {response.status_code}")
                    return {
                        "error": f"API error: {response.status_code}",
                        "analysis_type": analysis_type
                    }
                    
        except Exception as e:
            logger.error(f"Error calling Stitch AI: {str(e)}")
            return {
                "error": str(e),
                "analysis_type": analysis_type
            }


# Singleton instance
_stitch_ai_client: Optional[StitchAIClient] = None


def get_stitch_ai_client() -> StitchAIClient:
    """Get or create Stitch AI client"""
    global _stitch_ai_client
    
    if _stitch_ai_client is None:
        _stitch_ai_client = StitchAIClient()
        
    return _stitch_ai_client
