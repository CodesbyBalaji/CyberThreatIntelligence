"""
Advanced LLM-Powered Threat Analytics Module
Provides intelligent threat analysis, prediction, and automated response generation.
"""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
import requests

import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LLMProvider:
    """Base class for LLM providers."""
    
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate text from prompt."""
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""
    
    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = base_url or config.OLLAMA_URL
        self.model = model or config.DEFAULT_MODEL
    
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate text using Ollama."""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            response = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False
                },
                timeout=60
            )
            response.raise_for_status()
            
            return response.json()['message']['content']
            
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return f"Error: {str(e)}"


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""
    
    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or config.OPENAI_API_KEY
        self.model = model or config.LLM_MODELS['openai']
    
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate text using OpenAI."""
        if not self.api_key:
            return "OpenAI API key not configured"
        
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            response = client.chat.completions.create(
                model=self.model,
                messages=messages
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            return f"Error: {str(e)}"


class GoogleProvider(LLMProvider):
    """Google Gemini provider."""
    
    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or config.GOOGLE_API_KEY
        self.model = model or config.LLM_MODELS['google']
    
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate text using Google Gemini."""
        if not self.api_key:
            return "Google API key not configured"
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            
            model = genai.GenerativeModel(self.model)
            
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"
            
            response = model.generate_content(full_prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Google generation failed: {e}")
            return f"Error: {str(e)}"


class AdvancedThreatAnalytics:
    """Advanced threat analytics powered by LLMs."""
    
    def __init__(self):
        self.llm = self._initialize_llm()
    
    def _initialize_llm(self) -> LLMProvider:
        """Initialize the configured LLM provider."""
        provider = config.LLM_PROVIDER.lower()
        
        if provider == 'openai':
            return OpenAIProvider()
        elif provider == 'google':
            return GoogleProvider()
        else:
            return OllamaProvider()
    
    def generate_threat_actor_profile(self, campaign_data: Dict) -> str:
        """
        Generate a detailed threat actor profile based on campaign data.
        
        Args:
            campaign_data: Campaign information including IOCs, TTPs, targets
        
        Returns:
            Detailed threat actor profile
        """
        system_prompt = """You are an expert cyber threat intelligence analyst specializing in threat actor profiling and attribution. Analyze the provided campaign data and generate a comprehensive threat actor profile."""
        
        prompt = f"""Analyze the following threat campaign data and generate a detailed threat actor profile:

Campaign Name: {campaign_data.get('name', 'Unknown')}
IOCs: {json.dumps(campaign_data.get('iocs', [])[:10], indent=2)}
TTPs: {json.dumps(campaign_data.get('ttps', [])[:10], indent=2)}
Targeted Sectors: {campaign_data.get('targeted_sectors', [])}
Targeted Countries: {campaign_data.get('targeted_countries', [])}

Generate a profile including:
1. Likely threat actor or group
2. Sophistication level (1-10)
3. Motivation (financial, espionage, hacktivism, etc.)
4. Capabilities and resources
5. Attribution confidence and reasoning
6. Historical context and similar campaigns
7. Recommended defensive measures"""
        
        return self.llm.generate(prompt, system_prompt)
    
    def predict_next_attack_vector(self, historical_data: List[Dict]) -> str:
        """
        Predict likely next attack vectors based on historical patterns.
        
        Args:
            historical_data: List of historical attack data
        
        Returns:
            Prediction of next attack vectors
        """
        system_prompt = """You are a predictive threat intelligence analyst. Analyze historical attack patterns and predict likely future attack vectors."""
        
        prompt = f"""Based on the following historical attack data, predict the most likely next attack vectors:

Historical Attacks:
{json.dumps(historical_data[:5], indent=2)}

Provide:
1. Top 3 most likely next attack vectors
2. Probability assessment for each
3. Indicators to watch for
4. Recommended proactive defenses
5. Timeline estimation"""
        
        return self.llm.generate(prompt, system_prompt)
    
    def generate_executive_report(self, threat_summary: Dict) -> str:
        """
        Generate an executive-level threat intelligence report.
        
        Args:
            threat_summary: Summary of threat intelligence data
        
        Returns:
            Executive report in markdown format
        """
        system_prompt = """You are a senior threat intelligence analyst preparing an executive briefing. Create clear, concise reports suitable for C-level executives."""
        
        prompt = f"""Generate an executive threat intelligence report based on this data:

Total Threats: {threat_summary.get('total_threats', 0)}
Active Campaigns: {threat_summary.get('active_campaigns', 0)}
Critical IOCs: {threat_summary.get('critical_iocs', 0)}
High-Risk TTPs: {threat_summary.get('high_risk_ttps', [])}
Affected Assets: {threat_summary.get('affected_assets', [])}
Time Period: {threat_summary.get('time_period', 'Last 30 days')}

Create a report with:
1. Executive Summary (3-4 sentences)
2. Key Findings (bullet points)
3. Risk Assessment (High/Medium/Low with justification)
4. Business Impact
5. Recommended Actions (prioritized)
6. Resource Requirements

Use clear, non-technical language suitable for executives."""
        
        return self.llm.generate(prompt, system_prompt)
    
    def contextualize_ioc(self, ioc_value: str, ioc_type: str, enrichment_data: Dict) -> str:
        """
        Provide context and explanation for an IOC.
        
        Args:
            ioc_value: The IOC value
            ioc_type: Type of IOC
            enrichment_data: Enrichment data from various sources
        
        Returns:
            Contextualized explanation
        """
        system_prompt = """You are a threat intelligence analyst explaining IOCs to security teams. Provide clear, actionable context."""
        
        prompt = f"""Explain the significance of this Indicator of Compromise:

IOC: {ioc_value}
Type: {ioc_type}
Enrichment Data: {json.dumps(enrichment_data, indent=2)}

Provide:
1. What this IOC represents
2. Threat level (Critical/High/Medium/Low)
3. Known associations (malware, campaigns, threat actors)
4. Recommended actions
5. Detection strategies
6. False positive likelihood"""
        
        return self.llm.generate(prompt, system_prompt)
    
    def generate_response_playbook(self, threat_data: Dict) -> str:
        """
        Generate an automated incident response playbook.
        
        Args:
            threat_data: Threat information
        
        Returns:
            Incident response playbook
        """
        system_prompt = """You are an incident response expert. Create detailed, actionable response playbooks following industry best practices."""
        
        prompt = f"""Generate an incident response playbook for this threat:

Threat Type: {threat_data.get('threat_type', 'Unknown')}
Severity: {threat_data.get('severity', 'Unknown')}
IOCs: {json.dumps(threat_data.get('iocs', [])[:5], indent=2)}
TTPs: {json.dumps(threat_data.get('ttps', [])[:5], indent=2)}
Affected Systems: {threat_data.get('affected_systems', [])}

Create a playbook with:
1. Immediate Actions (first 15 minutes)
2. Containment Steps
3. Eradication Procedures
4. Recovery Steps
5. Evidence Collection
6. Communication Plan
7. Post-Incident Activities

Include specific commands and tools where applicable."""
        
        return self.llm.generate(prompt, system_prompt)
    
    def generate_yara_rule(self, malware_analysis: Dict) -> str:
        """
        Generate YARA rules for malware detection.
        
        Args:
            malware_analysis: Malware analysis data
        
        Returns:
            YARA rule
        """
        system_prompt = """You are a malware analyst expert in writing YARA rules. Generate accurate, efficient YARA rules for malware detection."""
        
        prompt = f"""Generate a YARA rule for detecting this malware:

Malware Name: {malware_analysis.get('name', 'Unknown')}
Family: {malware_analysis.get('family', 'Unknown')}
File Hashes: {malware_analysis.get('hashes', [])}
Strings: {malware_analysis.get('strings', [])}
Behaviors: {malware_analysis.get('behaviors', [])}
File Type: {malware_analysis.get('file_type', 'Unknown')}

Create a YARA rule with:
1. Descriptive metadata
2. String patterns (hex and ASCII)
3. Condition logic
4. Comments explaining the detection logic

Ensure the rule is specific enough to avoid false positives but flexible enough to catch variants."""
        
        return self.llm.generate(prompt, system_prompt)
    
    def analyze_attack_campaign(self, campaign_data: Dict) -> str:
        """
        Perform deep analysis of an attack campaign.
        
        Args:
            campaign_data: Campaign data including documents, IOCs, TTPs
        
        Returns:
            Detailed campaign analysis
        """
        system_prompt = """You are a threat intelligence analyst specializing in campaign analysis and attribution."""
        
        prompt = f"""Analyze this attack campaign in detail:

Campaign: {campaign_data.get('name', 'Unknown')}
Duration: {campaign_data.get('duration', 'Unknown')}
Documents: {campaign_data.get('document_count', 0)}
IOCs: {len(campaign_data.get('iocs', []))}
TTPs: {len(campaign_data.get('ttps', []))}
Targets: {campaign_data.get('targets', [])}

Sample IOCs:
{json.dumps(campaign_data.get('iocs', [])[:10], indent=2)}

Sample TTPs:
{json.dumps(campaign_data.get('ttps', [])[:10], indent=2)}

Provide:
1. Campaign Overview
2. Attack Timeline
3. Kill Chain Analysis
4. Attribution Assessment
5. Victimology
6. Infrastructure Analysis
7. Recommendations"""
        
        return self.llm.generate(prompt, system_prompt)
    
    def generate_threat_hunting_queries(self, threat_data: Dict) -> str:
        """
        Generate threat hunting queries based on threat data.
        
        Args:
            threat_data: Threat information
        
        Returns:
            Threat hunting queries for various platforms
        """
        system_prompt = """You are a threat hunting expert. Generate effective hunting queries for multiple security platforms."""
        
        prompt = f"""Generate threat hunting queries for this threat:

Threat: {threat_data.get('name', 'Unknown')}
IOCs: {json.dumps(threat_data.get('iocs', [])[:10], indent=2)}
TTPs: {json.dumps(threat_data.get('ttps', [])[:5], indent=2)}

Generate queries for:
1. Splunk
2. Elastic/ELK
3. Microsoft Sentinel (KQL)
4. Windows Event Logs (PowerShell)
5. Linux (grep/awk)

Include explanations for each query."""
        
        return self.llm.generate(prompt, system_prompt)
    
    def assess_threat_score(self, threat_data: Dict) -> Dict:
        """
        Calculate a comprehensive threat score.
        
        Args:
            threat_data: Threat information
        
        Returns:
            Threat score and breakdown
        """
        # Calculate component scores
        ioc_score = min(len(threat_data.get('iocs', [])) * 2, 20)
        
        ttp_severity_map = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}
        ttp_score = sum(ttp_severity_map.get(ttp.get('severity', 'low'), 5) 
                       for ttp in threat_data.get('ttps', []))
        ttp_score = min(ttp_score, 30)
        
        source_reputation = threat_data.get('source_reputation', 50)
        
        # Temporal relevance (newer = higher score)
        days_old = threat_data.get('days_old', 30)
        temporal_score = max(15 - (days_old / 2), 0)
        
        campaign_score = 20 if threat_data.get('campaign_associated') else 0
        
        # Weighted total
        weights = config.THREAT_SCORE_WEIGHTS
        total_score = (
            ioc_score * weights['ioc_count'] +
            ttp_score * weights['ttp_severity'] +
            source_reputation * weights['source_reputation'] +
            temporal_score * weights['temporal_relevance'] +
            campaign_score * weights['campaign_association']
        )
        
        # Normalize to 0-100
        total_score = min(max(total_score, 0), 100)
        
        # Determine risk level
        if total_score >= 80:
            risk_level = 'CRITICAL'
        elif total_score >= 60:
            risk_level = 'HIGH'
        elif total_score >= 40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_score': round(total_score, 2),
            'risk_level': risk_level,
            'breakdown': {
                'ioc_score': round(ioc_score * weights['ioc_count'], 2),
                'ttp_score': round(ttp_score * weights['ttp_severity'], 2),
                'source_reputation': round(source_reputation * weights['source_reputation'], 2),
                'temporal_score': round(temporal_score * weights['temporal_relevance'], 2),
                'campaign_score': round(campaign_score * weights['campaign_association'], 2)
            }
        }
    
    def generate_threat_narrative(self, threat_data: Dict) -> str:
        """
        Generate a natural language narrative of a threat.
        
        Args:
            threat_data: Comprehensive threat data
        
        Returns:
            Natural language threat story
        """
        system_prompt = """You are a threat intelligence storyteller. Create engaging, accurate narratives that explain complex threats in an accessible way."""
        
        prompt = f"""Create a compelling narrative story about this cyber threat:

{json.dumps(threat_data, indent=2)}

Write a narrative that:
1. Tells the story chronologically
2. Explains the threat actor's objectives
3. Describes the attack methodology
4. Highlights key moments and decisions
5. Explains the impact
6. Concludes with lessons learned

Make it engaging but technically accurate. Use analogies where helpful."""
        
        return self.llm.generate(prompt, system_prompt)
