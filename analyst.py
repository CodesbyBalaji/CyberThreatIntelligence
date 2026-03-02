"""
Analyst module for the LLM-powered Threat Fusion Engine.
Handles LLM-powered queries and threat analysis.
"""

import json
import requests
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatAnalyst:
    """LLM-powered threat intelligence analyst."""

    def __init__(self, storage):
        """
        Initialize the analyst.

        Args:
            storage: ThreatStorage instance
        """
        self.storage = storage
        self.prompt_templates = self._load_prompt_templates()
        
        # Load configuration
        import config
        # Load configuration
        import config
        self.provider = 'ollama'  # Forced to Ollama
        self.ollama_url = config.OLLAMA_URL
        
        # We only use Ollama now
        self.google_api_key = None

    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load prompt templates for different query types."""
        return {
            'ioc_analysis': """You are a cybersecurity threat intelligence analyst. Given the IOC "{ioc}" and the following evidence snippets, provide a comprehensive analysis:

Evidence:
{evidence}

Please provide:
1. **Risk Summary** (2-3 sentences): Brief assessment of the threat level and impact
2. **ATT&CK Techniques**: List likely MITRE ATT&CK techniques used (with IDs)
3. **Suggested Mitigations** (3-5 bullet points): Specific countermeasures to implement
4. **Confidence Score** (0-1): Your confidence in this analysis
5. **Citations**: Reference the source documents that support your findings

Format your response clearly with the above sections.""",

            'campaign_analysis': """You are a cybersecurity threat intelligence analyst. Analyze the following campaign information:

Campaign: {campaign_name}
Documents: {document_count}
IOCs: {ioc_summary}
TTPs: {ttp_summary}

Evidence snippets:
{evidence}

Please provide:
1. **Executive Summary** (3-4 sentences): High-level overview of the campaign
2. **Attack Timeline**: Sequence of attack phases and techniques
3. **Attribution Assessment**: Likely threat actor characteristics or groups
4. **Impact Analysis**: Potential damage and affected sectors
5. **Defensive Recommendations**: Specific security measures to implement
6. **Confidence Score** (0-1): Your confidence in this analysis

Format your response clearly with the above sections.""",

            'general_query': """You are a cybersecurity threat intelligence analyst. Answer the following query based on the provided evidence:

Query: {query}

Evidence:
{evidence}

Please provide a comprehensive answer that:
1. Directly addresses the query
2. References specific evidence from the documents
3. Includes relevant threat intelligence context
4. Provides actionable insights where applicable
5. Cites sources that support your analysis

If the evidence is insufficient to fully answer the query, clearly state what additional information would be needed."""
        }

    def analyze_ioc(self, ioc_value: str) -> Dict:
        """
        Analyze a specific IOC using LLM and stored intelligence.

        Args:
            ioc_value: IOC value to analyze

        Returns:
            Analysis results dictionary
        """
        logger.info(f"Analyzing IOC: {ioc_value}")

        # Search for IOC in database
        ioc_data = self.storage.search_ioc(ioc_value)

        if not ioc_data:
            return {
                'ioc': ioc_value,
                'found': False,
                'message': 'IOC not found in database'
            }

        # Get related documents
        document_ids = json.loads(ioc_data.get('document_ids', '[]'))
        evidence_snippets = []

        for doc_id in document_ids:
            doc = self.storage.get_document_by_id(doc_id)
            if doc:
                # Extract relevant context around the IOC
                content = doc['content']
                ioc_pos = content.lower().find(ioc_value.lower())
                if ioc_pos != -1:
                    start = max(0, ioc_pos - 200)
                    end = min(len(content), ioc_pos + len(ioc_value) + 200)
                    context = content[start:end].strip()

                    evidence_snippets.append({
                        'document_id': doc_id,
                        'title': doc['title'],
                        'context': context,
                        'source_type': doc['source_type']
                    })

        # Build evidence text for LLM
        evidence_text = ""
        for i, snippet in enumerate(evidence_snippets, 1):
            evidence_text += f"[{i}] {snippet['title']} ({snippet['source_type']}):\n"
            evidence_text += f"{snippet['context']}\n\n"

        # Generate LLM analysis
        prompt = self.prompt_templates['ioc_analysis'].format(
            ioc=ioc_value,
            evidence=evidence_text
        )

        llm_response = self._query_llm(prompt)

        return {
            'ioc': ioc_value,
            'found': True,
            'ioc_data': ioc_data,
            'evidence_count': len(evidence_snippets),
            'llm_analysis': llm_response,
            'evidence_snippets': evidence_snippets,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def analyze_campaign(self, campaign_id: int) -> Dict:
        """
        Analyze a specific campaign using LLM.

        Args:
            campaign_id: Campaign ID to analyze

        Returns:
            Campaign analysis results
        """
        logger.info(f"Analyzing campaign: {campaign_id}")

        # Get campaign data
        campaigns = self.storage.get_campaigns()
        campaign = next((c for c in campaigns if c['id'] == campaign_id), None)

        if not campaign:
            return {
                'campaign_id': campaign_id,
                'found': False,
                'message': 'Campaign not found'
            }

        # Get campaign documents
        document_ids = json.loads(campaign.get('document_ids', '[]'))
        campaign_docs = []
        evidence_snippets = []

        for doc_id in document_ids:
            doc = self.storage.get_document_by_id(doc_id)
            if doc:
                campaign_docs.append(doc)
                # Take first 300 characters as evidence
                evidence_snippets.append({
                    'document_id': doc_id,
                    'title': doc['title'],
                    'snippet': doc['content'][:300] + "...",
                    'source_type': doc['source_type']
                })

        # Get IOCs and TTPs for the campaign
        campaign_iocs = []
        campaign_ttps = []

        for doc_id in document_ids:
            iocs = self.storage.get_iocs_by_document(doc_id)
            ttps = self.storage.get_ttps_by_document(doc_id)
            campaign_iocs.extend(iocs)
            campaign_ttps.extend(ttps)

        # Summarize IOCs and TTPs
        ioc_summary = self._summarize_iocs(campaign_iocs)
        ttp_summary = self._summarize_ttps(campaign_ttps)

        # Build evidence text
        evidence_text = ""
        for i, snippet in enumerate(evidence_snippets, 1):
            evidence_text += f"[{i}] {snippet['title']} ({snippet['source_type']}):\n"
            evidence_text += f"{snippet['snippet']}\n\n"

        # Generate LLM analysis
        prompt = self.prompt_templates['campaign_analysis'].format(
            campaign_name=campaign['name'],
            document_count=len(campaign_docs),
            ioc_summary=ioc_summary,
            ttp_summary=ttp_summary,
            evidence=evidence_text
        )

        llm_response = self._query_llm(prompt)

        return {
            'campaign_id': campaign_id,
            'found': True,
            'campaign_data': campaign,
            'document_count': len(campaign_docs),
            'ioc_count': len(campaign_iocs),
            'ttp_count': len(campaign_ttps),
            'llm_analysis': llm_response,
            'evidence_snippets': evidence_snippets,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def answer_query(self, query: str, max_results: int = 5) -> Dict:
        """
        Answer a natural language query about threats.

        Args:
            query: Natural language query
            max_results: Maximum number of documents to retrieve

        Returns:
            Query response dictionary
        """
        logger.info(f"Processing query: {query}")

        # Perform semantic search
        search_results = self.storage.semantic_search(query, top_k=max_results)

        if not search_results:
            return {
                'query': query,
                'found_evidence': False,
                'message': 'No relevant documents found for this query'
            }

        # Get documents and build evidence
        evidence_snippets = []
        for doc_id, similarity in search_results:
            doc = self.storage.get_document_by_id(doc_id)
            if doc:
                evidence_snippets.append({
                    'document_id': doc_id,
                    'title': doc['title'],
                    'similarity': similarity,
                    'snippet': self._extract_relevant_snippet(doc['content'], query),
                    'source_type': doc['source_type']
                })

        # Build evidence text for LLM
        evidence_text = ""
        for i, snippet in enumerate(evidence_snippets, 1):
            evidence_text += f"[{i}] {snippet['title']} (similarity: {snippet['similarity']:.2f}, {snippet['source_type']}):\n"
            evidence_text += f"{snippet['snippet']}\n\n"

        # Generate LLM response
        prompt = self.prompt_templates['general_query'].format(
            query=query,
            evidence=evidence_text
        )

        llm_response = self._query_llm(prompt)

        return {
            'query': query,
            'found_evidence': True,
            'evidence_count': len(evidence_snippets),
            'llm_response': llm_response,
            'evidence_snippets': evidence_snippets,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def _extract_relevant_snippet(self, content: str, query: str, max_length: int = 400) -> str:
        """Extract most relevant snippet from content based on query."""
        query_words = query.lower().split()
        content_lower = content.lower()

        # Find the position with the most query word matches
        best_pos = 0
        best_score = 0
        window_size = max_length // 2

        for i in range(0, len(content) - window_size, 50):
            window = content_lower[i:i + window_size]
            score = sum(1 for word in query_words if word in window)

            if score > best_score:
                best_score = score
                best_pos = i

        # Extract snippet around best position
        start = max(0, best_pos - window_size // 2)
        end = min(len(content), start + max_length)

        snippet = content[start:end].strip()

        # Try to break at sentence boundaries
        if start > 0:
            sentence_start = snippet.find('. ') + 2
            if sentence_start > 1:
                snippet = snippet[sentence_start:]

        if end < len(content):
            sentence_end = snippet.rfind('. ')
            if sentence_end > max_length // 2:
                snippet = snippet[:sentence_end + 1]

        return snippet

    def _summarize_iocs(self, iocs: List[Dict]) -> str:
        """Create a summary of IOCs."""
        if not iocs:
            return "No IOCs found"

        ioc_types = {}
        for ioc in iocs:
            ioc_type = ioc.get('type', 'unknown')
            if ioc_type not in ioc_types:
                ioc_types[ioc_type] = 0
            ioc_types[ioc_type] += 1

        summary_parts = []
        for ioc_type, count in ioc_types.items():
            summary_parts.append(f"{count} {ioc_type}(s)")

        return ", ".join(summary_parts)

    def _summarize_ttps(self, ttps: List[Dict]) -> str:
        """Create a summary of TTPs."""
        if not ttps:
            return "No TTPs identified"

        technique_names = [ttp.get('name', 'Unknown') for ttp in ttps[:5]]
        if len(ttps) > 5:
            technique_names.append(f"and {len(ttps) - 5} more")

        return ", ".join(technique_names)

    def _query_llm(self, prompt: str) -> str:
        """
        Dispatch query to Ollama.
        """
        return self._query_ollama(prompt)

    # _query_google method removed as requested

    def _query_ollama(self, prompt: str) -> str:
        """
        Query Ollama API for LLM processing.
        """
        import time
        from performance import monitor

        # Record start time
        start_time = time.time()
        
        try:
            import config
            model = config.LLM_MODELS.get('ollama', 'gemma2:2b')
            
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "top_p": 0.8,
                        "num_predict": 1000
                    }
                },
                timeout=60
            )

            # Record LLM latency
            duration = time.time() - start_time
            monitor.record_latency('llm_query_analyst', duration, {'model': model})

            if response.status_code == 200:
                result = response.json()
                return result.get('response', 'No response generated')
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return f"Error querying LLM: HTTP {response.status_code}"
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to query Ollama: {str(e)}")
            return f"Error querying LLM: {str(e)}"

    def get_threat_summary(self, time_period_days: int = 30) -> Dict:
        """
        Get a summary of recent threat activity.

        Args:
            time_period_days: Number of days to look back

        Returns:
            Threat summary dictionary
        """
        # Get recent documents
        documents = self.storage.get_documents(limit=50)

        # Filter by time period if timestamps are available
        recent_docs = []
        for doc in documents:
            if doc.get('timestamp'):
                try:
                    doc_time = datetime.fromisoformat(doc['timestamp'].replace('Z', '+00:00'))
                    if (datetime.now(doc_time.tzinfo) - doc_time).days <= time_period_days:
                        recent_docs.append(doc)
                except:
                    recent_docs.append(doc)  # Include if timestamp parsing fails
            else:
                recent_docs.append(doc)

        # Get campaigns
        campaigns = self.storage.get_campaigns()

        # Build summary
        summary = {
            'time_period_days': time_period_days,
            'total_documents': len(recent_docs),
            'source_breakdown': {},
            'campaign_count': len(campaigns),
            'top_campaigns': campaigns[:5],
            'analysis_timestamp': datetime.now().isoformat()
        }

        # Source type breakdown
        for doc in recent_docs:
            source_type = doc.get('source_type', 'unknown')
            if source_type not in summary['source_breakdown']:
                summary['source_breakdown'][source_type] = 0
            summary['source_breakdown'][source_type] += 1

        return summary

    def suggest_investigations(self, analysis_result: Dict) -> List[str]:
        """
        Suggest follow-up investigations based on analysis results.

        Args:
            analysis_result: Result from previous analysis

        Returns:
            List of investigation suggestions
        """
        suggestions = []

        if 'ioc_data' in analysis_result:
            ioc_data = analysis_result['ioc_data']
            ioc_type = ioc_data.get('type')

            if ioc_type == 'domain':
                suggestions.extend([
                    "Check DNS resolution history for this domain",
                    "Look for subdomains of this domain",
                    "Search for related domains with similar registration patterns"
                ])
            elif ioc_type == 'ipv4':
                suggestions.extend([
                    "Check IP geolocation and hosting provider",
                    "Look for other domains hosted on this IP",
                    "Search for network traffic to/from this IP"
                ])
            elif ioc_type in ['md5', 'sha1', 'sha256']:
                suggestions.extend([
                    "Search VirusTotal for additional context",
                    "Look for similar file hashes",
                    "Check if hash appears in other campaigns"
                ])

        if 'campaign_data' in analysis_result:
            suggestions.extend([
                "Investigate attribution patterns for this campaign",
                "Look for similar campaigns with overlapping IOCs",
                "Check for related infrastructure patterns"
            ])

        # Generic suggestions
        suggestions.extend([
            "Search for related TTPs in recent reports",
            "Check for mentions in threat intelligence feeds",
            "Correlate with internal security logs"
        ])

        return suggestions[:5]  # Return top 5 suggestions
