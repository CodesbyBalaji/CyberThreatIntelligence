"""
IOC and TTP extraction module for the LLM-powered Threat Fusion Engine.
Uses regex patterns and LLM prompts to extract indicators and TTPs.
"""

import re
import json
import requests
from typing import List, Dict, Optional, Tuple
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatExtractor:
    """Main class for extracting IOCs and TTPs from text."""

    def __init__(self):
        """
        Initialize the extractor.
        """
        import config
        # Load configuration
        import config
        self.provider = 'ollama'
        self.ollama_url = config.OLLAMA_URL
        self.google_api_key = None

        # Regex patterns for IOC extraction
        self.ioc_patterns = {
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"\[\]{}|\\^`]+',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'cve': r'CVE-\d{4}-\d{4,}',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'file_hash': r'\b[a-fA-F0-9]{32,64}\b'
        }

        # Common false positive domains to filter out
        self.fp_domains = {
            'example.com', 'example.org', 'example.net', 'localhost',
            'google.com', 'microsoft.com', 'apple.com', 'github.com',
            'twitter.com', 'facebook.com', 'linkedin.com', 'youtube.com'
        }

        # Load MITRE ATT&CK mapping data
        self.attack_techniques = self._load_attack_techniques()

    def _load_attack_techniques(self) -> Dict:
        """Load MITRE ATT&CK technique mappings."""
        # Simplified ATT&CK technique mapping
        return {
            'T1059': {'name': 'Command and Scripting Interpreter', 'sub_techniques': {
                'T1059.001': 'PowerShell',
                'T1059.003': 'Windows Command Shell',
                'T1059.006': 'Python',
                'T1059.007': 'JavaScript'
            }},
            'T1055': {'name': 'Process Injection', 'sub_techniques': {}},
            'T1082': {'name': 'System Information Discovery', 'sub_techniques': {}},
            'T1083': {'name': 'File and Directory Discovery', 'sub_techniques': {}},
            'T1105': {'name': 'Ingress Tool Transfer', 'sub_techniques': {}},
            'T1566': {'name': 'Phishing', 'sub_techniques': {
                'T1566.001': 'Spearphishing Attachment',
                'T1566.002': 'Spearphishing Link'
            }},
            'T1027': {'name': 'Obfuscated Files or Information', 'sub_techniques': {}},
            'T1486': {'name': 'Data Encrypted for Impact', 'sub_techniques': {}},
            'T1490': {'name': 'Inhibit System Recovery', 'sub_techniques': {}},
            'T1562': {'name': 'Impair Defenses', 'sub_techniques': {}}
        }

    def extract_iocs_regex(self, text: str) -> List[Dict]:
        """
        Extract IOCs using regex patterns.

        Args:
            text: Text to extract IOCs from

        Returns:
            List of IOC dictionaries
        """
        iocs = []

        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)

            for match in matches:
                value = match.group().strip()

                # Filter out false positives
                if self._is_valid_ioc(value, ioc_type):
                    iocs.append({
                        'value': value,
                        'type': ioc_type,
                        'confidence': self._calculate_confidence(value, ioc_type),
                        'context': self._extract_context(text, match.start(), match.end()),
                        'extraction_method': 'regex'
                    })

        # Deduplicate IOCs
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc['value'].lower(), ioc['type'])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def _is_valid_ioc(self, value: str, ioc_type: str) -> bool:
        """
        Validate if an extracted value is a legitimate IOC.

        Args:
            value: Extracted value
            ioc_type: Type of IOC

        Returns:
            True if valid IOC
        """
        if ioc_type == 'domain':
            # Filter out common false positive domains
            if value.lower() in self.fp_domains:
                return False

            # Must have valid TLD
            parts = value.split('.')
            if len(parts) < 2 or len(parts[-1]) < 2:
                return False

        elif ioc_type == 'ipv4':
            # Validate IP address ranges
            try:
                octets = [int(x) for x in value.split('.')]
                if any(octet > 255 for octet in octets):
                    return False
                # Filter out private/reserved ranges for some contexts
                if octets[0] in [10, 127] or (octets[0] == 192 and octets[1] == 168):
                    return False
            except ValueError:
                return False

        elif ioc_type in ['md5', 'sha1', 'sha256']:
            # Ensure proper length and hex characters
            expected_lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}
            if len(value) != expected_lengths[ioc_type]:
                return False

        return True

    def _calculate_confidence(self, value: str, ioc_type: str) -> float:
        """Calculate confidence score for an IOC."""
        base_confidence = 0.8

        # Adjust based on type and context
        if ioc_type in ['md5', 'sha1', 'sha256']:
            base_confidence = 0.9  # Hashes are usually high confidence
        elif ioc_type == 'cve':
            base_confidence = 0.95  # CVEs are very reliable
        elif ioc_type == 'domain':
            # Lower confidence for common-looking domains
            if any(word in value.lower() for word in ['test', 'sample', 'demo']):
                base_confidence = 0.6

        return base_confidence

    def _extract_context(self, text: str, start: int, end: int, window: int = 50) -> str:
        """Extract surrounding context for an IOC."""
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        context = text[context_start:context_end].strip()

        # Replace the IOC with placeholder for anonymization if needed
        ioc_text = text[start:end]
        context = context.replace(ioc_text, '[IOC]')

        return context

    def extract_ttps_llm(self, text: str) -> List[Dict]:
        """
        Extract TTPs using LLM prompts.

        Args:
            text: Text to analyze

        Returns:
            List of TTP dictionaries
        """
        try:
            prompt = self._build_ttp_prompt(text)
            # Use default model configured in _query_llm
            response = self._query_llm(prompt)

            if response:
                ttps = self._parse_ttp_response(response)
                return ttps

        except Exception as e:
            logger.error(f"Failed to extract TTPs with LLM: {str(e)}")

        # Fallback to keyword-based extraction
        return self.extract_ttps_keywords(text)

    def extract_ttps_keywords(self, text: str) -> List[Dict]:
        """
        Extract TTPs using keyword matching as fallback.

        Args:
            text: Text to analyze

        Returns:
            List of TTP dictionaries
        """
        ttps = []
        text_lower = text.lower()

        # Keyword mappings to MITRE techniques
        technique_keywords = {
            'T1059.001': ['powershell', 'ps1', 'invoke-expression', 'iex'],
            'T1059.003': ['cmd.exe', 'command prompt', 'batch script', 'cmd /c'],
            'T1566.001': ['phishing', 'malicious attachment', 'email attachment'],
            'T1566.002': ['malicious link', 'phishing link', 'malicious url'],
            'T1027': ['obfuscation', 'encoded', 'base64', 'encrypted'],
            'T1486': ['ransomware', 'file encryption', 'data encrypted'],
            'T1105': ['download', 'remote file', 'file transfer'],
            'T1082': ['system information', 'os version', 'system discovery']
        }

        for technique_id, keywords in technique_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    technique_info = self._get_technique_info(technique_id)
                    ttps.append({
                        'mitre_id': technique_id,
                        'name': technique_info['name'],
                        'confidence': 0.7,
                        'context': self._find_keyword_context(text, keyword),
                        'extraction_method': 'keyword'
                    })
                    break  # Only add once per technique

        return ttps

    def _build_ttp_prompt(self, text: str) -> str:
        """Build prompt for TTP extraction."""
        prompt = f"""You are a cybersecurity analyst. Analyze the following text and map it to MITRE ATT&CK techniques.

Return a JSON array with the following structure:
[{{"mitre_id": "T1059.001", "name": "PowerShell", "confidence": 0.9, "context": "relevant text snippet"}}]

Only include techniques that are clearly described or implied in the text. Be conservative with confidence scores.

Text to analyze:
{text[:2000]}  # Limit text length for API

Return only the JSON array, no other text."""

        return prompt

    def _query_llm(self, prompt: str, model: str = None) -> Optional[str]:
        """Dispatch query to Ollama."""
        return self._query_ollama(prompt, model)

    # _query_google method removed as requested

    def _query_ollama(self, prompt: str, model: str = None) -> Optional[str]:
        """
        Query Ollama API for LLM processing.

        Args:
            prompt: Input prompt
            model: Model name to use

        Returns:
            Model response or None if failed
        """
        import time
        import config  # Import config to get the correct model
        from performance import monitor
        
        if model is None:
            # properly use the configured model from config.py
            model = config.LLM_MODELS.get('ollama', 'llama3.2:3b')
            
        start_time = time.time()
        
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.9
                    }
                },
                timeout=30
            )

            # Record latency
            duration = time.time() - start_time
            monitor.record_latency('llm_query_extraction', duration, {'model': model})

            if response.status_code == 200:
                result = response.json()
                return result.get('response', '')
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to query Ollama: {str(e)}")
            return None

    def _parse_ttp_response(self, response: str) -> List[Dict]:
        """Parse LLM response for TTPs."""
        try:
            # Try to extract JSON from response
            json_start = response.find('[')
            json_end = response.rfind(']') + 1

            if json_start != -1 and json_end != 0:
                json_text = response[json_start:json_end]
                ttps = json.loads(json_text)

                # Validate and enhance TTP data
                validated_ttps = []
                for ttp in ttps:
                    if self._validate_ttp(ttp):
                        validated_ttps.append(ttp)

                return validated_ttps

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse TTP JSON: {str(e)}")

        return []

    def _validate_ttp(self, ttp: Dict) -> bool:
        """Validate TTP data structure."""
        required_fields = ['mitre_id', 'name', 'confidence']

        for field in required_fields:
            if field not in ttp:
                return False

        # Validate MITRE ID format
        if not re.match(r'T\d{4}(\.\d{3})?', ttp['mitre_id']):
            return False

        # Validate confidence range
        if not 0 <= ttp['confidence'] <= 1:
            return False

        return True

    def _get_technique_info(self, technique_id: str) -> Dict:
        """Get technique information from ATT&CK data."""
        # Handle sub-techniques
        main_id = technique_id.split('.')[0]

        if main_id in self.attack_techniques:
            main_technique = self.attack_techniques[main_id]

            if '.' in technique_id and technique_id in main_technique['sub_techniques']:
                return {
                    'name': main_technique['sub_techniques'][technique_id],
                    'parent': main_technique['name']
                }
            else:
                return {'name': main_technique['name']}

        return {'name': f'Unknown Technique {technique_id}'}

    def _find_keyword_context(self, text: str, keyword: str, window: int = 100) -> str:
        """Find context around a keyword."""
        keyword_pos = text.lower().find(keyword.lower())
        if keyword_pos == -1:
            return ""

        start = max(0, keyword_pos - window)
        end = min(len(text), keyword_pos + len(keyword) + window)

        return text[start:end].strip()

    def verify_iocs_llm(self, iocs: List[Dict]) -> List[Dict]:
        """
        Verify extracted IOCs using LLM.

        Args:
            iocs: List of IOCs to verify

        Returns:
            List of verified IOCs
        """
        if not iocs:
            return []

        try:
            ioc_values = [ioc['value'] for ioc in iocs[:10]]  # Limit for API
            prompt = self._build_ioc_verification_prompt(ioc_values)
            response = self._query_llm(prompt)

            if response:
                verified_iocs = self._parse_ioc_verification_response(response, iocs)
                return verified_iocs

        except Exception as e:
            logger.error(f"Failed to verify IOCs with LLM: {str(e)}")

        # Return original IOCs if verification fails
        return iocs

    def _build_ioc_verification_prompt(self, ioc_values: List[str]) -> str:
        """Build prompt for IOC verification."""
        iocs_text = "\n".join(f"- {ioc}" for ioc in ioc_values)

        prompt = f"""You are a cybersecurity analyst. Verify if these extracted entities are valid IOCs (indicators of compromise).

Return a JSON array with only the valid IOCs and their confidence scores (0-1):
[{{"value": "malicious.example.com", "confidence": 0.9}}]

Consider whether each item looks like a legitimate:
- IP address (not private/internal)
- Domain name (suspicious/malicious looking)
- File hash (proper format)
- CVE identifier
- Email address (potentially malicious)

IOCs to verify:
{iocs_text}

Return only the JSON array with valid IOCs:"""

        return prompt

    def _parse_ioc_verification_response(self, response: str, original_iocs: List[Dict]) -> List[Dict]:
        """Parse IOC verification response."""
        try:
            json_start = response.find('[')
            json_end = response.rfind(']') + 1

            if json_start != -1 and json_end != 0:
                json_text = response[json_start:json_end]
                verified = json.loads(json_text)

                # Match with original IOCs and update confidence
                verified_iocs = []
                for original in original_iocs:
                    for ver in verified:
                        if original['value'] == ver['value']:
                            original['confidence'] = ver.get('confidence', original['confidence'])
                            original['llm_verified'] = True
                            verified_iocs.append(original)
                            break

                return verified_iocs

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse IOC verification JSON: {str(e)}")

        return original_iocs

    def extract_all(self, text: str) -> Dict:
        """
        Extract all IOCs and TTPs from text.

        Args:
            text: Text to analyze

        Returns:
            Dictionary with extracted data
        """
        import time
        from performance import monitor
        
        logger.info("Starting IOC and TTP extraction")
        start_time = time.time()

        # Extract IOCs
        iocs = self.extract_iocs_regex(text)
        verified_iocs = self.verify_iocs_llm(iocs)

        # Extract TTPs
        ttps = self.extract_ttps_llm(text)

        # Generate summary
        summary = self._generate_summary(text, verified_iocs, ttps)

        # Record total extraction time
        duration = time.time() - start_time
        monitor.record_latency('extraction_total', duration, {'text_length': len(text)})

        result = {
            'iocs': verified_iocs,
            'ttps': ttps,
            'summary': summary,
            'extraction_timestamp': datetime.now().isoformat(),
            'processing_time': duration
        }

        logger.info(f"Extracted {len(verified_iocs)} IOCs and {len(ttps)} TTPs in {duration:.2f}s")
        return result

    def _generate_summary(self, text: str, iocs: List[Dict], ttps: List[Dict]) -> str:
        """Generate a brief summary of the extracted intelligence."""
        summary_parts = []

        if iocs:
            ioc_types = {}
            for ioc in iocs:
                ioc_type = ioc['type']
                if ioc_type not in ioc_types:
                    ioc_types[ioc_type] = 0
                ioc_types[ioc_type] += 1

            ioc_summary = ", ".join([f"{count} {ioc_type}(s)" for ioc_type, count in ioc_types.items()])
            summary_parts.append(f"IOCs found: {ioc_summary}")

        if ttps:
            ttp_names = [ttp['name'] for ttp in ttps[:3]]  # Top 3
            if len(ttps) > 3:
                ttp_names.append(f"and {len(ttps) - 3} more")
            summary_parts.append(f"TTPs identified: {', '.join(ttp_names)}")

        if not summary_parts:
            return "No significant threat indicators found in this document."

        return ". ".join(summary_parts) + "."
