"""
Data ingestion module for the LLM-powered Threat Fusion Engine.
Handles ingestion from security blogs, OSINT feeds, and dark web posts.
"""

import requests
import json
import re
from typing import Dict, List, Optional
from datetime import datetime
from newspaper import Article
from bs4 import BeautifulSoup
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIngestor:
    """Main class for ingesting threat intelligence from various sources."""

    def __init__(self):
        """Initialize the ingestor."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def ingest_blog_post(self, url: str) -> Optional[Dict]:
        """
        Ingest a security blog post using newspaper3k.

        Args:
            url: URL of the blog post

        Returns:
            Parsed document dictionary or None if failed
        """
        try:
            article = Article(url)
            article.download()
            article.parse()

            # Clean and normalize text
            content = self._clean_text(article.text)

            return {
                'url': url,
                'title': article.title or 'Untitled',
                'content': content,
                'source_type': 'blog',
                'metadata': {
                    'authors': article.authors,
                    'publish_date': article.publish_date.isoformat() if article.publish_date else None,
                    'summary': article.summary[:500] if article.summary else None,
                    'top_image': article.top_image
                }
            }

        except Exception as e:
            logger.error(f"Failed to ingest blog post {url}: {str(e)}")
            return None

    def ingest_osint_feed(self, feed_type: str = 'alientvault_otx') -> List[Dict]:
        """
        Ingest OSINT feeds. For demo purposes, uses simulated data.
        In production, this would connect to real APIs.

        Args:
            feed_type: Type of OSINT feed to ingest

        Returns:
            List of parsed documents
        """
        if feed_type == 'alientvault_otx':
            return self._simulate_otx_feed()
        elif feed_type == 'abuse_ch':
            return self._simulate_abuse_ch_feed()
        else:
            logger.warning(f"Unknown feed type: {feed_type}")
            return []

    def _simulate_otx_feed(self) -> List[Dict]:
        """Simulate AlienVault OTX feed data."""
        sample_data = [
            {
                'id': 'pulse_001',
                'name': 'APT29 Infrastructure Updates',
                'description': 'New command and control infrastructure associated with APT29 group targeting government entities. Observed domains use DGA algorithms and utilize compromised legitimate sites as redirectors.',
                'indicators': [
                    {'type': 'domain', 'indicator': 'apt29-c2.example.com'},
                    {'type': 'ip', 'indicator': '192.168.1.100'},
                    {'type': 'hash_md5', 'indicator': '5d41402abc4b2a76b9719d911017c592'}
                ],
                'created': '2024-01-15T10:30:00Z'
            },
            {
                'id': 'pulse_002', 
                'name': 'Ransomware Campaign Targeting Healthcare',
                'description': 'Ongoing ransomware campaign using spear-phishing emails with malicious PDF attachments. Targets healthcare organizations with customized lures related to patient data regulations.',
                'indicators': [
                    {'type': 'hash_sha256', 'indicator': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                    {'type': 'domain', 'indicator': 'ransomware-pay.onion'},
                    {'type': 'email', 'indicator': 'admin@malicious-healthcare.com'}
                ],
                'created': '2024-01-14T08:45:00Z'
            }
        ]

        documents = []
        for item in sample_data:
            content = f"{item['name']}\n\n{item['description']}\n\nIndicators:\n"
            for indicator in item['indicators']:
                content += f"- {indicator['type']}: {indicator['indicator']}\n"

            documents.append({
                'url': f"https://otx.alienvault.com/pulse/{item['id']}",
                'title': item['name'],
                'content': self._clean_text(content),
                'source_type': 'osint',
                'metadata': {
                    'feed_type': 'alientvault_otx',
                    'pulse_id': item['id'],
                    'created': item['created']
                }
            })

        return documents

    def _simulate_abuse_ch_feed(self) -> List[Dict]:
        """Simulate Abuse.ch feed data."""
        sample_data = [
            {
                'timestamp': '2024-01-15T12:00:00Z',
                'url_status': 'online',
                'url': 'http://malware-drop.example.com/payload.exe',
                'host': 'malware-drop.example.com',
                'tags': ['exe', 'trojan', 'stealer']
            },
            {
                'timestamp': '2024-01-15T11:30:00Z', 
                'url_status': 'offline',
                'url': 'https://phishing-site.example.com/login',
                'host': 'phishing-site.example.com',
                'tags': ['phishing', 'credential_theft']
            }
        ]

        documents = []
        for item in sample_data:
            content = f"Malicious URL detected: {item['url']}\nHost: {item['host']}\nStatus: {item['url_status']}\nTags: {', '.join(item['tags'])}"

            documents.append({
                'url': f"https://urlhaus.abuse.ch/url/{hash(item['url']) % 1000000}/",
                'title': f"Malicious URL: {item['host']}",
                'content': self._clean_text(content),
                'source_type': 'osint',
                'metadata': {
                    'feed_type': 'abuse_ch',
                    'timestamp': item['timestamp'],
                    'url_status': item['url_status'],
                    'tags': item['tags']
                }
            })

        return documents

    def ingest_darkweb_posts(self, data_dir: str = 'data/darkweb') -> List[Dict]:
        """
        Ingest simulated dark web forum posts from local files.

        Args:
            data_dir: Directory containing dark web post files

        Returns:
            List of parsed documents
        """
        documents = []
        data_path = Path(data_dir)

        if not data_path.exists():
            logger.warning(f"Dark web data directory not found: {data_dir}")
            return []

        for file_path in data_path.glob('*.json'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    posts = json.load(f)

                for post in posts:
                    content = f"Forum: {post.get('forum', 'Unknown')}\n"
                    content += f"Author: {post.get('author', 'Anonymous')}\n"
                    content += f"Subject: {post.get('subject', 'No Subject')}\n\n"
                    content += post.get('content', '')

                    documents.append({
                        'url': f"darkweb://{post.get('forum', 'unknown')}/{post.get('post_id', 'unknown')}",
                        'title': post.get('subject', 'Dark Web Post'),
                        'content': self._clean_text(content),
                        'source_type': 'darkweb',
                        'metadata': {
                            'forum': post.get('forum'),
                            'author': post.get('author'),
                            'post_id': post.get('post_id'),
                            'timestamp': post.get('timestamp'),
                            'thread_id': post.get('thread_id')
                        }
                    })

            except Exception as e:
                logger.error(f"Failed to parse dark web file {file_path}: {str(e)}")

        return documents

    def ingest_kafka_stream(self, topic: str, bootstrap_servers: str = 'localhost:9092', limit: int = 10) -> List[Dict]:
        """
        Ingest threat intelligence from a Kafka stream.
        In a real deployment, this would be a continuous consumer.
        For demo purposes, we'll read a batch of messages or simulate if Kafka isn't available.
        """
        documents = []
        try:
            from kafka import KafkaConsumer
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=[bootstrap_servers],
                auto_offset_reset='earliest',
                enable_auto_commit=True,
                group_id='threat-fusion-group',
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                consumer_timeout_ms=1000
            )
            
            for i, message in enumerate(consumer):
                if i >= limit:
                    break
                
                data = message.value
                content = data.get('content', '')
                if not content:
                    content = f"Event from {data.get('source', 'unknown')}: {data.get('event_type', 'unknown')}\n{json.dumps(data)}"
                
                documents.append({
                    'url': f"kafka://{topic}/{message.partition}/{message.offset}",
                    'title': data.get('title', f"Kafka Event - {topic}"),
                    'content': self._clean_text(content),
                    'source_type': 'kafka_stream',
                    'metadata': {
                        'topic': topic,
                        'partition': message.partition,
                        'offset': message.offset,
                        'timestamp': datetime.fromtimestamp(message.timestamp / 1000).isoformat() if hasattr(message, 'timestamp') and message.timestamp else datetime.now().isoformat(),
                        'original_data': data
                    }
                })
            consumer.close()
            logger.info(f"Ingested {len(documents)} events from Kafka topic {topic}")
        except ImportError:
            logger.warning("kafka-python not installed. Simulating Kafka stream ingestion.")
            # Simulate kafka data
            import time
            sim_data = [
                {"title": "Suspicious Login Stream", "content": "Multiple failed logins from IP 185.15.2.1 followed by success for user admin", "source": "SIEM"},
                {"title": "DDoS Alert", "content": "High volume of UDP traffic detected targeting primary load balancer", "source": "NIDS"},
                {"title": "C2 Traffic Pattern", "content": "Beaconing behavior detected to unknown domain malware-control.abc", "source": "EDR"}
            ]
            for i, data in enumerate(sim_data):
                documents.append({
                    'url': f"kafka://{topic}/0/{int(time.time()) + i}",
                    'title': data['title'],
                    'content': self._clean_text(data['content']),
                    'source_type': 'kafka_stream',
                    'metadata': {
                        'topic': topic,
                        'timestamp': datetime.now().isoformat(),
                        'simulated': True
                    }
                })
        except Exception as e:
            logger.error(f"Failed to ingest from Kafka topic {topic}: {str(e)}")
            
        return documents

    def ingest_text_file(self, file_path: str, source_type: str = 'manual') -> Optional[Dict]:
        """
        Ingest a plain text file.

        Args:
            file_path: Path to the text file
            source_type: Type of source for categorization

        Returns:
            Parsed document dictionary or None if failed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            return {
                'url': f"file://{file_path}",
                'title': Path(file_path).stem,
                'content': self._clean_text(content),
                'source_type': source_type,
                'metadata': {
                    'file_path': file_path,
                    'file_size': Path(file_path).stat().st_size
                }
            }

        except Exception as e:
            logger.error(f"Failed to ingest text file {file_path}: {str(e)}")
            return None

    def _clean_text(self, text: str) -> str:
        """
        Clean and normalize text content.

        Args:
            text: Raw text to clean

        Returns:
            Cleaned text
        """
        if not text:
            return ""

        # Remove HTML tags
        text = BeautifulSoup(text, 'html.parser').get_text()

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'\n+', '\n', text)

        # Remove excessive punctuation
        text = re.sub(r'[!]{2,}', '!', text)
        text = re.sub(r'[?]{2,}', '?', text)

        # Strip leading/trailing whitespace
        text = text.strip()

        return text

    def chunk_document(self, content: str, chunk_size: int = 1000, overlap: int = 100) -> List[str]:
        """
        Split long documents into chunks for processing.

        Args:
            content: Document content
            chunk_size: Maximum size of each chunk in characters
            overlap: Number of characters to overlap between chunks

        Returns:
            List of text chunks
        """
        if len(content) <= chunk_size:
            return [content]

        chunks = []
        start = 0

        while start < len(content):
            end = start + chunk_size

            # Try to break at sentence boundary
            if end < len(content):
                # Look for sentence ending within last 100 characters
                sentence_end = content.rfind('.', start + chunk_size - 100, end)
                if sentence_end != -1:
                    end = sentence_end + 1

            chunk = content[start:end].strip()
            if chunk:
                chunks.append(chunk)

            start = end - overlap
            if start >= len(content):
                break

        return chunks

    def batch_ingest_urls(self, urls: List[str]) -> List[Dict]:
        """
        Ingest multiple URLs in batch.

        Args:
            urls: List of URLs to ingest

        Returns:
            List of successfully parsed documents
        """
        documents = []

        for url in urls:
            doc = self.ingest_blog_post(url)
            if doc:
                documents.append(doc)
                logger.info(f"Successfully ingested: {url}")
            else:
                logger.warning(f"Failed to ingest: {url}")

        return documents
