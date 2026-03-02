"""
Advanced Threat Intelligence Feeds Module
Integrates with real-time threat intelligence sources using their official APIs.
"""

import requests
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import time
from pathlib import Path
import hashlib

import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter for API calls."""
    
    def __init__(self, calls: int, period: int):
        self.calls = calls
        self.period = period
        self.timestamps = []
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded."""
        now = time.time()
        # Remove timestamps older than the period
        self.timestamps = [ts for ts in self.timestamps if now - ts < self.period]
        
        if len(self.timestamps) >= self.calls:
            sleep_time = self.period - (now - self.timestamps[0])
            if sleep_time > 0:
                logger.info(f"Rate limit reached, waiting {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
        
        self.timestamps.append(now)


class ThreatFeedAPI:
    """Base class for threat intelligence feed APIs."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatFusionEngine/2.0'
        })
        self.cache_dir = config.CACHE_DIR / 'feeds'
        self.cache_dir.mkdir(exist_ok=True)
    
    def _get_cache_path(self, feed_name: str) -> Path:
        """Get cache file path for a feed."""
        return self.cache_dir / f"{feed_name}_{datetime.now().strftime('%Y%m%d')}.json"
    
    def _load_from_cache(self, feed_name: str, max_age_hours: int = 1) -> Optional[List[Dict]]:
        """Load data from cache if available and fresh."""
        cache_path = self._get_cache_path(feed_name)
        
        if cache_path.exists():
            age = time.time() - cache_path.stat().st_mtime
            if age < max_age_hours * 3600:
                try:
                    with open(cache_path, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    logger.error(f"Failed to load cache: {e}")
        
        return None
    
    def _save_to_cache(self, feed_name: str, data: List[Dict]):
        """Save data to cache."""
        cache_path = self._get_cache_path(feed_name)
        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")


class AlienVaultOTX(ThreatFeedAPI):
    """AlienVault Open Threat Exchange API integration."""
    
    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or config.ALIENVAULT_OTX_API_KEY
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.rate_limiter = RateLimiter(**config.RATE_LIMITS['otx'])
        
        if self.api_key:
            self.session.headers.update({'X-OTX-API-KEY': self.api_key})
    
    def get_pulses(self, modified_since: Optional[datetime] = None, limit: int = 50) -> List[Dict]:
        """
        Get threat pulses from OTX.
        
        Args:
            modified_since: Only get pulses modified after this date
            limit: Maximum number of pulses to retrieve
        
        Returns:
            List of pulse documents
        """
        if not self.api_key:
            logger.warning("OTX API key not configured, using demo data")
            return self._get_demo_pulses()
        
        # Check cache first
        cached = self._load_from_cache('otx_pulses')
        if cached:
            logger.info(f"Loaded {len(cached)} pulses from cache")
            return cached[:limit]
        
        try:
            self.rate_limiter.wait_if_needed()
            
            params = {'limit': limit}
            if modified_since:
                params['modified_since'] = modified_since.isoformat()
            
            response = self.session.get(
                f"{self.base_url}/pulses/subscribed",
                params=params,
                timeout=config.FEED_TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json()
            pulses = data.get('results', [])
            
            documents = []
            for pulse in pulses:
                doc = self._parse_pulse(pulse)
                if doc:
                    documents.append(doc)
            
            # Cache the results
            self._save_to_cache('otx_pulses', documents)
            
            logger.info(f"Retrieved {len(documents)} pulses from OTX")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to fetch OTX pulses: {e}")
            return self._get_demo_pulses()
    
    def _parse_pulse(self, pulse: Dict) -> Dict:
        """Parse OTX pulse into document format."""
        indicators = pulse.get('indicators', [])
        
        content = f"{pulse.get('name', 'Untitled Pulse')}\n\n"
        content += f"{pulse.get('description', '')}\n\n"
        content += "Indicators:\n"
        
        for indicator in indicators[:20]:  # Limit to first 20
            ind_type = indicator.get('type', 'unknown')
            ind_value = indicator.get('indicator', '')
            content += f"- {ind_type}: {ind_value}\n"
        
        tags = pulse.get('tags', [])
        if tags:
            content += f"\nTags: {', '.join(tags)}\n"
        
        return {
            'url': f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
            'title': pulse.get('name', 'OTX Pulse'),
            'content': content,
            'source_type': 'otx',
            'metadata': {
                'pulse_id': pulse.get('id'),
                'author': pulse.get('author_name'),
                'created': pulse.get('created'),
                'modified': pulse.get('modified'),
                'tags': tags,
                'tlp': pulse.get('TLP', 'white'),
                'indicator_count': len(indicators),
                'adversary': pulse.get('adversary', ''),
                'targeted_countries': pulse.get('targeted_countries', [])
            }
        }
    
    def _get_demo_pulses(self) -> List[Dict]:
        """Return demo pulses when API key is not available."""
        return [
            {
                'url': 'https://otx.alienvault.com/pulse/demo1',
                'title': 'APT29 Cozy Bear Infrastructure Update Q4 2024',
                'content': '''APT29 Cozy Bear Infrastructure Update Q4 2024

Recent intelligence indicates APT29 (Cozy Bear) has deployed new command and control infrastructure targeting government and diplomatic entities. The campaign utilizes sophisticated domain generation algorithms and leverages compromised legitimate websites as redirectors.

Indicators:
- domain: cozy-bear-c2.example.com
- domain: diplomatic-portal.example.org
- ip: 185.220.101.45
- hash_sha256: a3b2c1d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
- email: admin@apt29-phish.example.com

Tags: APT29, Cozy Bear, Government, Espionage, Russia''',
                'source_type': 'otx',
                'metadata': {
                    'pulse_id': 'demo_pulse_001',
                    'author': 'ThreatIntel Team',
                    'created': (datetime.now() - timedelta(days=2)).isoformat(),
                    'tags': ['APT29', 'Cozy Bear', 'Government', 'Espionage'],
                    'tlp': 'amber',
                    'indicator_count': 5,
                    'adversary': 'APT29',
                    'targeted_countries': ['US', 'UK', 'EU']
                }
            },
            {
                'url': 'https://otx.alienvault.com/pulse/demo2',
                'title': 'LockBit 3.0 Ransomware Campaign - Healthcare Sector',
                'content': '''LockBit 3.0 Ransomware Campaign - Healthcare Sector

Active ransomware campaign targeting healthcare organizations using spear-phishing with malicious PDF attachments. The campaign shows high sophistication with customized lures related to patient data regulations and HIPAA compliance.

Indicators:
- hash_md5: 5d41402abc4b2a76b9719d911017c592
- hash_sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- domain: lockbit-payment.onion
- domain: healthcare-compliance.example.com
- ip: 192.168.100.50

Tags: LockBit, Ransomware, Healthcare, Phishing''',
                'source_type': 'otx',
                'metadata': {
                    'pulse_id': 'demo_pulse_002',
                    'author': 'Healthcare-ISAC',
                    'created': (datetime.now() - timedelta(days=1)).isoformat(),
                    'tags': ['LockBit', 'Ransomware', 'Healthcare'],
                    'tlp': 'amber',
                    'indicator_count': 5,
                    'adversary': 'LockBit',
                    'targeted_countries': ['US', 'CA']
                }
            }
        ]


class VirusTotalAPI(ThreatFeedAPI):
    """VirusTotal API integration for IOC enrichment."""
    
    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limiter = RateLimiter(**config.RATE_LIMITS['virustotal'])
        
        if self.api_key:
            self.session.headers.update({'x-apikey': self.api_key})
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """
        Enrich an IOC with VirusTotal data.
        
        Args:
            ioc_value: The IOC value (IP, domain, hash, URL)
            ioc_type: Type of IOC
        
        Returns:
            Enrichment data or None
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        try:
            self.rate_limiter.wait_if_needed()
            
            # Map IOC type to VT endpoint
            endpoint_map = {
                'ip': f'ip_addresses/{ioc_value}',
                'domain': f'domains/{ioc_value}',
                'url': f'urls/{self._encode_url(ioc_value)}',
                'hash_md5': f'files/{ioc_value}',
                'hash_sha256': f'files/{ioc_value}',
                'hash_sha1': f'files/{ioc_value}'
            }
            
            endpoint = endpoint_map.get(ioc_type)
            if not endpoint:
                return None
            
            response = self.session.get(
                f"{self.base_url}/{endpoint}",
                timeout=config.FEED_TIMEOUT
            )
            
            if response.status_code == 404:
                return {'found': False, 'message': 'IOC not found in VirusTotal'}
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_vt_response(data, ioc_type)
            
        except Exception as e:
            logger.error(f"Failed to enrich IOC with VirusTotal: {e}")
            return None
    
    def _encode_url(self, url: str) -> str:
        """Encode URL for VT API."""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    def _parse_vt_response(self, data: Dict, ioc_type: str) -> Dict:
        """Parse VirusTotal response."""
        attributes = data.get('data', {}).get('attributes', {})
        
        if ioc_type in ['ip', 'domain']:
            last_analysis = attributes.get('last_analysis_stats', {})
            return {
                'found': True,
                'malicious': last_analysis.get('malicious', 0),
                'suspicious': last_analysis.get('suspicious', 0),
                'harmless': last_analysis.get('harmless', 0),
                'reputation': attributes.get('reputation', 0),
                'country': attributes.get('country', ''),
                'as_owner': attributes.get('as_owner', ''),
                'last_analysis_date': attributes.get('last_analysis_date', '')
            }
        elif 'hash' in ioc_type:
            last_analysis = attributes.get('last_analysis_stats', {})
            return {
                'found': True,
                'malicious': last_analysis.get('malicious', 0),
                'suspicious': last_analysis.get('suspicious', 0),
                'file_type': attributes.get('type_description', ''),
                'size': attributes.get('size', 0),
                'names': attributes.get('names', [])[:5],
                'signature_info': attributes.get('signature_info', {})
            }
        
        return {'found': True, 'data': attributes}


class AbuseIPDBAPI(ThreatFeedAPI):
    """AbuseIPDB API integration for IP reputation."""
    
    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or config.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.rate_limiter = RateLimiter(**config.RATE_LIMITS['abuseipdb'])
        
        if self.api_key:
            self.session.headers.update({'Key': self.api_key})
    
    def check_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Check IP reputation on AbuseIPDB.
        
        Args:
            ip_address: IP address to check
        
        Returns:
            IP reputation data
        """
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return None
        
        try:
            self.rate_limiter.wait_if_needed()
            
            response = self.session.get(
                f"{self.base_url}/check",
                params={'ipAddress': ip_address, 'maxAgeInDays': 90},
                timeout=config.FEED_TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json().get('data', {})
            
            return {
                'ip': ip_address,
                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country_code': data.get('countryCode', ''),
                'usage_type': data.get('usageType', ''),
                'isp': data.get('isp', ''),
                'is_whitelisted': data.get('isWhitelisted', False),
                'last_reported': data.get('lastReportedAt', '')
            }
            
        except Exception as e:
            logger.error(f"Failed to check IP on AbuseIPDB: {e}")
            return None


class URLhausAPI(ThreatFeedAPI):
    """URLhaus API integration for malicious URLs."""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://urlhaus-api.abuse.ch/v1"
    
    def get_recent_urls(self, limit: int = 100) -> List[Dict]:
        """Get recent malicious URLs from URLhaus using CSV feed."""
        
        # Check cache
        cached = self._load_from_cache('urlhaus')
        if cached:
            return cached[:limit]
        
        try:
            # Use CSV feed as API is restricted/changed
            response = self.session.get(
                "https://urlhaus.abuse.ch/downloads/csv_recent/",
                timeout=config.FEED_TIMEOUT
            )
            response.raise_for_status()
            
            import csv
            import io
            
            # Parse CSV content
            content = response.text
            f = io.StringIO(content)
            reader = csv.reader(f)
            
            documents = []
            for row in reader:
                # Skip comments and empty lines
                if not row or row[0].startswith('#'):
                    continue
                
                # CSV format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                if len(row) >= 8:
                    url_data = {
                        'id': row[0],
                        'dateadded': row[1],
                        'url': row[2],
                        'url_status': row[3],
                        'threat': row[5],
                        'tags': row[6].split(',') if row[6] else [],
                        'urlhaus_link': row[7],
                        'reporter': row[8]
                    }
                    
                    doc = self._parse_url(url_data)
                    if doc:
                        documents.append(doc)
                        if len(documents) >= limit:
                            break
            
            self._save_to_cache('urlhaus', documents)
            logger.info(f"Retrieved {len(documents)} URLs from URLhaus")
            
            return documents
            
        except Exception as e:
            logger.error(f"Failed to fetch URLhaus data: {e}")
            return []
    
    def _parse_url(self, url_data: Dict) -> Dict:
        """Parse URLhaus entry into document format."""
        url = url_data.get('url', '')
        threat = url_data.get('threat', 'unknown')
        tags = url_data.get('tags', [])
        
        content = f"Malicious URL detected: {url}\n"
        content += f"Threat Type: {threat}\n"
        content += f"Status: {url_data.get('url_status', 'unknown')}\n"
        
        if tags:
            content += f"Tags: {', '.join(tags)}\n"
        
        return {
            'url': f"https://urlhaus.abuse.ch/url/{url_data.get('id', '')}/",
            'title': f"Malicious URL: {threat}",
            'content': content,
            'source_type': 'urlhaus',
            'metadata': {
                'malicious_url': url,
                'threat_type': threat,
                'tags': tags,
                'date_added': url_data.get('dateadded', ''),
                'reporter': url_data.get('reporter', '')
            }
        }


class ThreatFoxAPI(ThreatFeedAPI):
    """ThreatFox API integration for IOCs."""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://threatfox-api.abuse.ch/api/v1"
    
    def get_recent_iocs(self, days: int = 7) -> List[Dict]:
        """Get recent IOCs from ThreatFox."""
        
        cached = self._load_from_cache('threatfox')
        if cached:
            return cached
        
        try:
            # Use JSON export as API requires auth/is flaky
            export_url = "https://threatfox.abuse.ch/export/json/recent/"
            response = self.session.get(export_url, timeout=config.FEED_TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            
            iocs = []
            # The export format is a dict where values are lists of IOCs
            for key, item_list in data.items():
                if isinstance(item_list, list):
                    iocs.extend(item_list)
            
            documents = []
            for ioc_data in iocs[:100]:
                doc = self._parse_ioc(ioc_data)
                if doc:
                    documents.append(doc)
            
            self._save_to_cache('threatfox', documents)
            logger.info(f"Retrieved {len(documents)} IOCs from ThreatFox")
            
            return documents
            
        except Exception as e:
            logger.error(f"Failed to fetch ThreatFox data: {e}")
            return []
    
    def _parse_ioc(self, ioc_data: Dict) -> Dict:
        """Parse ThreatFox IOC into document format."""
        # Handle both API and Export formats
        ioc_value = ioc_data.get('ioc_value') or ioc_data.get('ioc', '')
        ioc_type = ioc_data.get('ioc_type', '')
        malware = ioc_data.get('malware_printable') or ioc_data.get('malware', 'unknown')
        
        content = f"IOC: {ioc_value}\n"
        content += f"Type: {ioc_type}\n"
        content += f"Malware: {malware}\n"
        content += f"Confidence: {ioc_data.get('confidence_level', 0)}%\n"
        
        tags = ioc_data.get('tags', [])
        if isinstance(tags, str):
            tags = [tags]
        if tags:
            content += f"Tags: {', '.join(tags)}\n"
        
        return {
            'url': f"https://threatfox.abuse.ch/ioc/{ioc_data.get('id', '')}/",
            'title': f"{malware} - {ioc_type}",
            'content': content,
            'source_type': 'threatfox',
            'metadata': {
                'ioc_value': ioc_value,
                'ioc_type': ioc_type,
                'malware': malware,
                'malware_alias': ioc_data.get('malware_alias', ''),
                'confidence': ioc_data.get('confidence_level', 0),
                'tags': tags,
                'first_seen': ioc_data.get('first_seen_utc') or ioc_data.get('first_seen', ''),
                'reporter': ioc_data.get('reporter', '')
            }
        }


class ThreatFeedAggregator:
    """Aggregates data from multiple threat intelligence feeds."""
    
    def __init__(self):
        self.otx = AlienVaultOTX()
        self.virustotal = VirusTotalAPI()
        self.abuseipdb = AbuseIPDBAPI()
        self.urlhaus = URLhausAPI()
        self.threatfox = ThreatFoxAPI()
    
    def fetch_all_feeds(self) -> Dict[str, List[Dict]]:
        """Fetch data from all configured feeds."""
        results = {}
        
        logger.info("Fetching threat intelligence from all sources...")
        
        # OTX Pulses
        try:
            results['otx'] = self.otx.get_pulses(limit=50)
        except Exception as e:
            logger.error(f"Failed to fetch OTX: {e}")
            results['otx'] = []
        
        # URLhaus
        try:
            results['urlhaus'] = self.urlhaus.get_recent_urls(limit=50)
        except Exception as e:
            logger.error(f"Failed to fetch URLhaus: {e}")
            results['urlhaus'] = []
        
        # ThreatFox
        try:
            results['threatfox'] = self.threatfox.get_recent_iocs(days=7)
        except Exception as e:
            logger.error(f"Failed to fetch ThreatFox: {e}")
            results['threatfox'] = []
        
        total = sum(len(docs) for docs in results.values())
        logger.info(f"Fetched {total} documents from {len(results)} sources")
        
        return results
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """Enrich an IOC with data from multiple sources."""
        enrichment = {
            'ioc': ioc_value,
            'type': ioc_type,
            'sources': {}
        }
        
        # VirusTotal enrichment
        if ioc_type in ['ip', 'domain', 'hash_md5', 'hash_sha256', 'hash_sha1', 'url']:
            vt_data = self.virustotal.enrich_ioc(ioc_value, ioc_type)
            if vt_data:
                enrichment['sources']['virustotal'] = vt_data
        
        # AbuseIPDB enrichment for IPs
        if ioc_type == 'ip':
            abuse_data = self.abuseipdb.check_ip(ioc_value)
            if abuse_data:
                enrichment['sources']['abuseipdb'] = abuse_data
        
        return enrichment
