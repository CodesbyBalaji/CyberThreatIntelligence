"""
Advanced IOC Enrichment Module
Automatically enriches IOCs with data from multiple threat intelligence sources.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json
from pathlib import Path

import config
from threat_feeds import ThreatFeedAggregator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnrichmentCache:
    """Cache for enrichment data to reduce API calls."""
    
    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or config.CACHE_DIR / 'enrichment'
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.ttl = config.ENRICHMENT_CACHE_TTL
    
    def get(self, ioc_value: str) -> Optional[Dict]:
        """Get cached enrichment data."""
        cache_file = self.cache_dir / f"{self._hash_ioc(ioc_value)}.json"
        
        if cache_file.exists():
            # Check if cache is still valid
            age = datetime.now().timestamp() - cache_file.stat().st_mtime
            if age < self.ttl:
                try:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    logger.error(f"Failed to load cache: {e}")
        
        return None
    
    def set(self, ioc_value: str, data: Dict):
        """Save enrichment data to cache."""
        cache_file = self.cache_dir / f"{self._hash_ioc(ioc_value)}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def _hash_ioc(self, ioc_value: str) -> str:
        """Create a safe filename from IOC value."""
        import hashlib
        return hashlib.md5(ioc_value.encode()).hexdigest()


class IOCEnricher:
    """Enriches IOCs with threat intelligence data."""
    
    def __init__(self):
        self.aggregator = ThreatFeedAggregator()
        self.cache = EnrichmentCache()
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str, force_refresh: bool = False) -> Dict:
        """
        Enrich an IOC with data from multiple sources.
        
        Args:
            ioc_value: The IOC value
            ioc_type: Type of IOC (ip, domain, hash, etc.)
            force_refresh: Force refresh even if cached
        
        Returns:
            Enriched IOC data
        """
        # Check cache first
        if not force_refresh and config.ENABLE_CACHING:
            cached = self.cache.get(ioc_value)
            if cached:
                logger.info(f"Using cached enrichment for {ioc_value}")
                return cached
        
        logger.info(f"Enriching IOC: {ioc_value} ({ioc_type})")
        
        enrichment = {
            'ioc': ioc_value,
            'type': ioc_type,
            'enriched_at': datetime.now().isoformat(),
            'sources': {},
            'summary': {}
        }
        
        # Get enrichment from aggregator
        try:
            source_data = self.aggregator.enrich_ioc(ioc_value, ioc_type)
            enrichment['sources'] = source_data.get('sources', {})
        except Exception as e:
            logger.error(f"Enrichment failed: {e}")
        
        # Generate summary
        enrichment['summary'] = self._generate_summary(enrichment)
        
        # Cache the result
        if config.ENABLE_CACHING:
            self.cache.set(ioc_value, enrichment)
        
        return enrichment
    
    def enrich_ioc_list(self, iocs: List[Dict]) -> List[Dict]:
        """
        Enrich a list of IOCs.
        
        Args:
            iocs: List of IOC dictionaries with 'value' and 'type'
        
        Returns:
            List of enriched IOCs
        """
        enriched = []
        
        for ioc in iocs:
            try:
                enrichment = self.enrich_ioc(ioc['value'], ioc['type'])
                enriched.append({
                    **ioc,
                    'enrichment': enrichment
                })
            except Exception as e:
                logger.error(f"Failed to enrich {ioc['value']}: {e}")
                enriched.append(ioc)
        
        return enriched
    
    def _generate_summary(self, enrichment: Dict) -> Dict:
        """Generate a summary of enrichment data."""
        summary = {
            'is_malicious': False,
            'confidence': 0.0,
            'threat_level': 'unknown',
            'reputation_score': 0,
            'first_seen': None,
            'last_seen': None,
            'associated_malware': [],
            'associated_campaigns': [],
            'tags': []
        }
        
        sources = enrichment.get('sources', {})
        
        # VirusTotal analysis
        if 'virustotal' in sources:
            vt = sources['virustotal']
            if vt.get('found'):
                malicious = vt.get('malicious', 0)
                suspicious = vt.get('suspicious', 0)
                harmless = vt.get('harmless', 0)
                
                total = malicious + suspicious + harmless
                if total > 0:
                    summary['is_malicious'] = malicious > 0
                    summary['confidence'] = malicious / total if total > 0 else 0
                    summary['reputation_score'] = vt.get('reputation', 0)
                
                if malicious > 10:
                    summary['threat_level'] = 'critical'
                elif malicious > 5:
                    summary['threat_level'] = 'high'
                elif malicious > 0:
                    summary['threat_level'] = 'medium'
                else:
                    summary['threat_level'] = 'low'
        
        # AbuseIPDB analysis
        if 'abuseipdb' in sources:
            abuse = sources['abuseipdb']
            abuse_score = abuse.get('abuse_confidence_score', 0)
            
            if abuse_score > 75:
                summary['is_malicious'] = True
                summary['threat_level'] = 'high'
                summary['confidence'] = max(summary['confidence'], abuse_score / 100)
        
        return summary


class AutoEnrichmentPipeline:
    """Automated enrichment pipeline for continuous IOC enrichment."""
    
    def __init__(self, storage):
        self.storage = storage
        self.enricher = IOCEnricher()
        self.enabled = config.AUTO_ENRICHMENT_ENABLED
    
    def process_new_iocs(self, document_id: str):
        """
        Automatically enrich IOCs from a newly ingested document.
        
        Args:
            document_id: ID of the document
        """
        if not self.enabled:
            return
        
        logger.info(f"Auto-enriching IOCs for document {document_id}")
        
        # Get IOCs for this document
        iocs = self.storage.get_iocs_by_document(document_id)
        
        if not iocs:
            return
        
        enriched_count = 0
        for ioc in iocs:
            try:
                enrichment = self.enricher.enrich_ioc(
                    ioc['value'],
                    ioc['type']
                )
                
                # Update IOC with enrichment data
                self.storage.update_ioc_enrichment(
                    ioc['id'],
                    enrichment
                )
                
                enriched_count += 1
                
            except Exception as e:
                logger.error(f"Failed to enrich IOC {ioc['value']}: {e}")
        
        logger.info(f"Enriched {enriched_count}/{len(iocs)} IOCs")
    
    def enrich_all_unenriched(self, limit: int = 100):
        """
        Enrich all IOCs that haven't been enriched yet.
        
        Args:
            limit: Maximum number of IOCs to enrich
        """
        if not self.enabled:
            return
        
        logger.info("Enriching unenriched IOCs...")
        
        # This would need a method in storage to get unenriched IOCs
        # For now, we'll skip the implementation
        pass
