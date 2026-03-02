"""
Fusion and correlation module for the LLM-powered Threat Fusion Engine.
Handles deduplication, correlation, and campaign clustering.
"""

import json
import numpy as np
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatFusion:
    """Main class for fusing and correlating threat intelligence."""

    def __init__(self, 
                 ioc_overlap_threshold: int = 2,
                 embedding_similarity_threshold: float = 0.85,
                 ttp_overlap_threshold: int = 1):
        """
        Initialize the fusion engine.

        Args:
            ioc_overlap_threshold: Minimum IOCs to share for correlation
            embedding_similarity_threshold: Minimum cosine similarity for document correlation
            ttp_overlap_threshold: Minimum TTPs to share for correlation
        """
        self.ioc_threshold = ioc_overlap_threshold
        self.embedding_threshold = embedding_similarity_threshold
        self.ttp_threshold = ttp_overlap_threshold

        # Initialize knowledge graph
        self.knowledge_graph = nx.Graph()

        # TF-IDF vectorizer for text similarity
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )

    def deduplicate_iocs(self, all_iocs: List[Dict]) -> List[Dict]:
        """
        Deduplicate IOCs across all documents.

        Args:
            all_iocs: List of all IOCs from all documents

        Returns:
            Deduplicated list of IOCs with merged metadata
        """
        ioc_groups = defaultdict(list)

        # Group IOCs by value and type
        for ioc in all_iocs:
            key = (ioc['value'].lower(), ioc['type'])
            ioc_groups[key].append(ioc)

        deduplicated = []
        for (value, ioc_type), ioc_list in ioc_groups.items():
            # Merge IOC data
            merged_ioc = {
                'value': ioc_list[0]['value'],  # Use original case
                'type': ioc_type,
                'confidence': max(ioc['confidence'] for ioc in ioc_list),
                'document_count': len(set(ioc.get('document_id') for ioc in ioc_list if ioc.get('document_id'))),
                'contexts': [ioc.get('context', '') for ioc in ioc_list if ioc.get('context')],
                'extraction_methods': list(set(ioc.get('extraction_method', 'unknown') for ioc in ioc_list)),
                'first_seen': min(ioc.get('first_seen', datetime.now().isoformat()) for ioc in ioc_list),
                'last_seen': max(ioc.get('last_seen', datetime.now().isoformat()) for ioc in ioc_list),
                'document_ids': list(set(ioc.get('document_id') for ioc in ioc_list if ioc.get('document_id')))
            }

            deduplicated.append(merged_ioc)

        logger.info(f"Deduplicated {len(all_iocs)} IOCs to {len(deduplicated)} unique IOCs")
        return deduplicated

    def compute_document_similarity(self, documents: List[Dict]) -> np.ndarray:
        """
        Compute pairwise similarity between documents using TF-IDF.

        Args:
            documents: List of document dictionaries

        Returns:
            Similarity matrix
        """
        if len(documents) < 2:
            return np.array([[1.0]])

        # Extract text content
        texts = [doc.get('content', '') for doc in documents]

        try:
            # Compute TF-IDF vectors
            tfidf_matrix = self.vectorizer.fit_transform(texts)

            # Compute cosine similarity
            similarity_matrix = cosine_similarity(tfidf_matrix)

            return similarity_matrix

        except Exception as e:
            logger.error(f"Failed to compute document similarity: {str(e)}")
            # Return identity matrix as fallback
            n = len(documents)
            return np.eye(n)

    def find_ioc_correlations(self, documents: List[Dict], document_iocs: Dict[int, List[Dict]]) -> List[Dict]:
        """
        Find documents that share IOCs.

        Args:
            documents: List of documents
            document_iocs: Mapping of document_id to IOCs

        Returns:
            List of correlation dictionaries
        """
        correlations = []
        doc_ids = list(document_iocs.keys())

        # Compare each pair of documents
        for i in range(len(doc_ids)):
            for j in range(i + 1, len(doc_ids)):
                doc_id1, doc_id2 = doc_ids[i], doc_ids[j]

                # Get IOC sets for comparison
                iocs1 = set((ioc['value'].lower(), ioc['type']) for ioc in document_iocs[doc_id1])
                iocs2 = set((ioc['value'].lower(), ioc['type']) for ioc in document_iocs[doc_id2])

                # Find shared IOCs
                shared_iocs = iocs1.intersection(iocs2)

                if len(shared_iocs) >= self.ioc_threshold:
                    correlation = {
                        'document_ids': [doc_id1, doc_id2],
                        'correlation_type': 'ioc_overlap',
                        'shared_iocs': list(shared_iocs),
                        'strength': len(shared_iocs) / max(len(iocs1), len(iocs2)),
                        'shared_count': len(shared_iocs)
                    }
                    correlations.append(correlation)

        logger.info(f"Found {len(correlations)} IOC-based correlations")
        return correlations

    def find_ttp_correlations(self, documents: List[Dict], document_ttps: Dict[int, List[Dict]]) -> List[Dict]:
        """
        Find documents that share TTPs.

        Args:
            documents: List of documents
            document_ttps: Mapping of document_id to TTPs

        Returns:
            List of correlation dictionaries
        """
        correlations = []
        doc_ids = list(document_ttps.keys())

        # Compare each pair of documents
        for i in range(len(doc_ids)):
            for j in range(i + 1, len(doc_ids)):
                doc_id1, doc_id2 = doc_ids[i], doc_ids[j]

                # Get TTP sets for comparison
                ttps1 = set(ttp['mitre_id'] for ttp in document_ttps[doc_id1])
                ttps2 = set(ttp['mitre_id'] for ttp in document_ttps[doc_id2])

                # Find shared TTPs
                shared_ttps = ttps1.intersection(ttps2)

                if len(shared_ttps) >= self.ttp_threshold:
                    correlation = {
                        'document_ids': [doc_id1, doc_id2],
                        'correlation_type': 'ttp_overlap',
                        'shared_ttps': list(shared_ttps),
                        'strength': len(shared_ttps) / max(len(ttps1), len(ttps2)),
                        'shared_count': len(shared_ttps)
                    }
                    correlations.append(correlation)

        logger.info(f"Found {len(correlations)} TTP-based correlations")
        return correlations

    def find_semantic_correlations(self, documents: List[Dict]) -> List[Dict]:
        """
        Find semantically similar documents using embeddings.

        Args:
            documents: List of documents

        Returns:
            List of correlation dictionaries
        """
        correlations = []

        if len(documents) < 2:
            return correlations

        # Compute document similarity matrix
        similarity_matrix = self.compute_document_similarity(documents)

        # Find highly similar document pairs
        for i in range(len(documents)):
            for j in range(i + 1, len(documents)):
                similarity = similarity_matrix[i][j]

                if similarity >= self.embedding_threshold:
                    correlation = {
                        'document_ids': [documents[i]['id'], documents[j]['id']],
                        'correlation_type': 'semantic_similarity',
                        'similarity_score': float(similarity),
                        'strength': similarity
                    }
                    correlations.append(correlation)

        logger.info(f"Found {len(correlations)} semantic correlations")
        return correlations

    def cluster_campaigns(self, documents: List[Dict], correlations: List[Dict]) -> List[Dict]:
        """
        Cluster documents into campaigns based on correlations.

        Args:
            documents: List of documents
            correlations: List of correlation dictionaries

        Returns:
            List of campaign clusters
        """
        # Build graph of document relationships
        doc_graph = nx.Graph()

        # Add all documents as nodes
        for doc in documents:
            doc_graph.add_node(doc['id'], **doc)

        # Add edges based on correlations
        for corr in correlations:
            doc_ids = corr['document_ids']
            if len(doc_ids) == 2:
                doc_graph.add_edge(
                    doc_ids[0], doc_ids[1],
                    correlation_type=corr['correlation_type'],
                    strength=corr['strength']
                )

        # Find connected components (campaigns)
        campaigns = []
        components = list(nx.connected_components(doc_graph))

        for i, component in enumerate(components):
            if len(component) > 1:  # Only clusters with multiple documents
                campaign_docs = [doc_graph.nodes[node_id] for node_id in component]

                # Calculate campaign metadata
                campaign = self._analyze_campaign(campaign_docs, i + 1)
                campaigns.append(campaign)

        logger.info(f"Identified {len(campaigns)} campaign clusters")
        return campaigns

    def _analyze_campaign(self, campaign_docs: List[Dict], campaign_id: int) -> Dict:
        """
        Analyze a campaign cluster to extract key characteristics.

        Args:
            campaign_docs: Documents in the campaign
            campaign_id: Campaign identifier

        Returns:
            Campaign analysis dictionary
        """
        # Extract timeline
        timestamps = []
        for doc in campaign_docs:
            if doc.get('timestamp'):
                try:
                    timestamps.append(datetime.fromisoformat(doc['timestamp'].replace('Z', '+00:00')))
                except:
                    pass

        timeline = {
            'start_date': min(timestamps).isoformat() if timestamps else None,
            'end_date': max(timestamps).isoformat() if timestamps else None,
            'duration_days': (max(timestamps) - min(timestamps)).days if len(timestamps) > 1 else 0
        }

        # Extract source types
        source_types = [doc.get('source_type', 'unknown') for doc in campaign_docs]
        source_distribution = {st: source_types.count(st) for st in set(source_types)}

        # Generate campaign name
        campaign_name = self._generate_campaign_name(campaign_docs, campaign_id)

        # Calculate confidence based on correlation strength and document count
        confidence = min(0.9, 0.5 + (len(campaign_docs) * 0.1))

        return {
            'id': campaign_id,
            'name': campaign_name,
            'document_ids': [doc['id'] for doc in campaign_docs],
            'document_count': len(campaign_docs),
            'confidence': confidence,
            'timeline': timeline,
            'source_distribution': source_distribution,
            'created_at': datetime.now().isoformat(),
            'metadata': {
                'analysis_method': 'graph_clustering',
                'cluster_size': len(campaign_docs)
            }
        }

    def _generate_campaign_name(self, campaign_docs: List[Dict], campaign_id: int) -> str:
        """Generate a descriptive name for the campaign."""
        # Extract common keywords from titles and content
        all_text = " ".join([
            doc.get('title', '') + " " + doc.get('content', '')[:200] 
            for doc in campaign_docs
        ]).lower()

        # Common threat actor/malware keywords
        threat_keywords = [
            'apt', 'ransomware', 'trojan', 'backdoor', 'phishing', 
            'malware', 'botnet', 'campaign', 'attack', 'threat'
        ]

        found_keywords = [kw for kw in threat_keywords if kw in all_text]

        if found_keywords:
            primary_keyword = found_keywords[0].title()
            return f"{primary_keyword} Campaign {campaign_id}"
        else:
            return f"Threat Campaign {campaign_id}"

    def build_knowledge_graph(self, documents: List[Dict], 
                            document_iocs: Dict[int, List[Dict]], 
                            document_ttps: Dict[int, List[Dict]], 
                            campaigns: List[Dict]) -> nx.Graph:
        """
        Build a knowledge graph of relationships.

        Args:
            documents: List of documents
            document_iocs: Document to IOC mappings
            document_ttps: Document to TTP mappings
            campaigns: List of campaigns

        Returns:
            NetworkX graph
        """
        self.knowledge_graph.clear()

        # Add document nodes
        for doc in documents:
            self.knowledge_graph.add_node(
                f"doc_{doc['id']}", 
                type='document',
                title=doc.get('title', ''),
                source_type=doc.get('source_type', ''),
                timestamp=doc.get('timestamp', '')
            )

        # Add IOC nodes and relationships
        for doc_id, iocs in document_iocs.items():
            for ioc in iocs:
                ioc_id = f"ioc_{ioc['type']}_{hash(ioc['value']) % 10000}"

                self.knowledge_graph.add_node(
                    ioc_id,
                    type='ioc',
                    ioc_type=ioc['type'],
                    value=ioc['value'],
                    confidence=ioc['confidence']
                )

                # Connect document to IOC
                self.knowledge_graph.add_edge(
                    f"doc_{doc_id}", 
                    ioc_id, 
                    relationship='contains'
                )

        # Add TTP nodes and relationships
        for doc_id, ttps in document_ttps.items():
            for ttp in ttps:
                ttp_id = f"ttp_{ttp['mitre_id']}"

                self.knowledge_graph.add_node(
                    ttp_id,
                    type='ttp',
                    mitre_id=ttp['mitre_id'],
                    name=ttp['name'],
                    confidence=ttp['confidence']
                )

                # Connect document to TTP
                self.knowledge_graph.add_edge(
                    f"doc_{doc_id}", 
                    ttp_id, 
                    relationship='exhibits'
                )

        # Add campaign nodes and relationships
        for campaign in campaigns:
            campaign_id = f"campaign_{campaign['id']}"

            self.knowledge_graph.add_node(
                campaign_id,
                type='campaign',
                name=campaign['name'],
                confidence=campaign['confidence'],
                document_count=campaign['document_count']
            )

            # Connect campaign to documents
            for doc_id in campaign['document_ids']:
                self.knowledge_graph.add_edge(
                    campaign_id, 
                    f"doc_{doc_id}", 
                    relationship='includes'
                )

        logger.info(f"Built knowledge graph with {self.knowledge_graph.number_of_nodes()} nodes and {self.knowledge_graph.number_of_edges()} edges")
        return self.knowledge_graph

    def save_knowledge_graph(self, filepath: str = "knowledge_graph.json"):
        """Save knowledge graph to JSON file."""
        graph_data = {
            'nodes': [
                {'id': node, **data} 
                for node, data in self.knowledge_graph.nodes(data=True)
            ],
            'edges': [
                {'source': source, 'target': target, **data}
                for source, target, data in self.knowledge_graph.edges(data=True)
            ]
        }

        with open(filepath, 'w') as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"Saved knowledge graph to {filepath}")

    def load_knowledge_graph(self, filepath: str = "knowledge_graph.json"):
        """Load knowledge graph from JSON file."""
        try:
            with open(filepath, 'r') as f:
                graph_data = json.load(f)

            self.knowledge_graph.clear()

            # Add nodes
            for node_data in graph_data['nodes']:
                node_id = node_data.pop('id')
                self.knowledge_graph.add_node(node_id, **node_data)

            # Add edges
            for edge_data in graph_data['edges']:
                source = edge_data.pop('source')
                target = edge_data.pop('target')
                self.knowledge_graph.add_edge(source, target, **edge_data)

            logger.info(f"Loaded knowledge graph from {filepath}")

        except Exception as e:
            logger.error(f"Failed to load knowledge graph: {str(e)}")

    def get_related_entities(self, entity_id: str, max_depth: int = 2) -> Dict:
        """
        Get entities related to a given entity.

        Args:
            entity_id: ID of the entity to find relations for
            max_depth: Maximum depth to traverse

        Returns:
            Dictionary of related entities
        """
        if entity_id not in self.knowledge_graph:
            return {}

        # Use BFS to find related entities
        related = {}
        visited = set()
        queue = [(entity_id, 0)]

        while queue:
            current_id, depth = queue.pop(0)

            if current_id in visited or depth > max_depth:
                continue

            visited.add(current_id)
            node_data = self.knowledge_graph.nodes[current_id]

            if depth > 0:  # Don't include the starting entity
                entity_type = node_data.get('type', 'unknown')
                if entity_type not in related:
                    related[entity_type] = []
                related[entity_type].append({
                    'id': current_id,
                    'depth': depth,
                    **node_data
                })

            # Add neighbors to queue
            for neighbor in self.knowledge_graph.neighbors(current_id):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

        return related

    def fusion_pipeline(self, documents: List[Dict], 
                       document_iocs: Dict[int, List[Dict]], 
                       document_ttps: Dict[int, List[Dict]]) -> Dict:
        """
        Run the complete fusion pipeline.

        Args:
            documents: List of documents
            document_iocs: Document to IOC mappings
            document_ttps: Document to TTP mappings

        Returns:
            Complete fusion results
        """
        logger.info("Starting fusion pipeline")

        # Step 1: Deduplicate IOCs
        all_iocs = []
        for doc_id, iocs in document_iocs.items():
            for ioc in iocs:
                ioc['document_id'] = doc_id
                all_iocs.append(ioc)

        deduplicated_iocs = self.deduplicate_iocs(all_iocs)

        # Step 2: Find correlations
        ioc_correlations = self.find_ioc_correlations(documents, document_iocs)
        ttp_correlations = self.find_ttp_correlations(documents, document_ttps)
        semantic_correlations = self.find_semantic_correlations(documents)

        all_correlations = ioc_correlations + ttp_correlations + semantic_correlations

        # Step 3: Cluster campaigns
        campaigns = self.cluster_campaigns(documents, all_correlations)

        # Step 4: Build knowledge graph
        knowledge_graph = self.build_knowledge_graph(documents, document_iocs, document_ttps, campaigns)

        # Step 5: Save knowledge graph
        self.save_knowledge_graph()

        results = {
            'deduplicated_iocs': deduplicated_iocs,
            'correlations': {
                'ioc_based': ioc_correlations,
                'ttp_based': ttp_correlations,
                'semantic': semantic_correlations,
                'total_count': len(all_correlations)
            },
            'campaigns': campaigns,
            'knowledge_graph_stats': {
                'nodes': knowledge_graph.number_of_nodes(),
                'edges': knowledge_graph.number_of_edges()
            },
            'processing_timestamp': datetime.now().isoformat()
        }

        logger.info("Fusion pipeline completed successfully")
        return results
