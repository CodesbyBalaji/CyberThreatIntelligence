"""
Storage module for the LLM-powered Threat Fusion Engine.
Handles SQLite database operations and FAISS vector storage.
"""

import sqlite3
import json
import pickle
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import faiss
from sentence_transformers import SentenceTransformer
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatStorage:
    """Main storage class handling both structured and vector data."""

    def __init__(self, db_path: str = "data/threat_fusion.db", vector_dim: int = 384):
        """
        Initialize storage with SQLite database and FAISS index.

        Args:
            db_path: Path to SQLite database file
            vector_dim: Dimension of sentence embeddings
        """
        self.db_path = db_path
        self.vector_dim = vector_dim
        self.conn = None
        self.faiss_index = None
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')

        self._init_database()
        self._init_faiss()

    def _init_database(self):
        """Initialize SQLite database with required tables."""
        # Ensure data directory exists
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        # Create tables
        cursor = self.conn.cursor()

        # Documents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_url TEXT,
                title TEXT,
                content TEXT,
                source_type TEXT,
                timestamp TEXT,
                processed BOOLEAN DEFAULT FALSE,
                metadata TEXT
            )
        """)

        # IOCs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT UNIQUE,
                type TEXT,
                confidence REAL,
                first_seen TEXT,
                last_seen TEXT,
                document_ids TEXT,
                metadata TEXT
            )
        """)

        # TTPs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ttps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mitre_id TEXT,
                name TEXT,
                confidence REAL,
                document_id INTEGER,
                text_context TEXT,
                FOREIGN KEY (document_id) REFERENCES documents (id)
            )
        """)

        # Campaigns table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                confidence REAL,
                document_ids TEXT,
                ioc_ids TEXT,
                ttp_ids TEXT,
                created_at TEXT,
                metadata TEXT
            )
        """)

        # Document embeddings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS document_embeddings (
                document_id INTEGER PRIMARY KEY,
                embedding BLOB,
                FOREIGN KEY (document_id) REFERENCES documents (id)
            )
        """)

        self.conn.commit()
        logger.info("Database initialized successfully")

    def _init_faiss(self):
        """Initialize FAISS index for vector similarity search."""
        try:
            # Try to load existing index
            self.faiss_index = faiss.read_index("data/threat_vectors.index")
            logger.info("Loaded existing FAISS index")
        except:
            # Create new index
            self.faiss_index = faiss.IndexFlatIP(self.vector_dim)
            logger.info("Created new FAISS index")

    def save_faiss_index(self):
        """Save FAISS index to disk."""
        faiss.write_index(self.faiss_index, "data/threat_vectors.index")

    def store_document(self, url: str, title: str, content: str, 
                      source_type: str, metadata: Dict = None) -> int:
        """
        Store a document in the database.

        Args:
            url: Source URL
            title: Document title
            content: Document content
            source_type: Type of source (blog, osint, darkweb)
            metadata: Additional metadata

        Returns:
            Document ID
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().isoformat()
        metadata_json = json.dumps(metadata or {})

        cursor.execute("""
            INSERT INTO documents (source_url, title, content, source_type, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (url, title, content, source_type, timestamp, metadata_json))

        doc_id = cursor.lastrowid
        self.conn.commit()

        # Generate and store embedding
        embedding = self.embedder.encode([content])[0]
        self._store_embedding(doc_id, embedding)

        logger.info(f"Stored document {doc_id}: {title[:50]}...")
        return doc_id

    def _store_embedding(self, document_id: int, embedding: np.ndarray):
        """Store document embedding in both database and FAISS index."""
        # Store in database
        cursor = self.conn.cursor()
        embedding_blob = pickle.dumps(embedding)
        cursor.execute("""
            INSERT OR REPLACE INTO document_embeddings (document_id, embedding)
            VALUES (?, ?)
        """, (document_id, embedding_blob))
        self.conn.commit()

        # Add to FAISS index
        embedding_normalized = embedding / np.linalg.norm(embedding)
        self.faiss_index.add(embedding_normalized.reshape(1, -1))
        self.save_faiss_index()

    def store_iocs(self, iocs: List[Dict], document_id: int):
        """
        Store extracted IOCs in the database.

        Args:
            iocs: List of IOC dictionaries
            document_id: Associated document ID
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().isoformat()

        for ioc in iocs:
            # Check if IOC already exists
            cursor.execute('SELECT id, document_ids FROM iocs WHERE value = ?', (ioc['value'],))
            existing = cursor.fetchone()

            if existing:
                # Update existing IOC
                doc_ids = json.loads(existing['document_ids'])
                if document_id not in doc_ids:
                    doc_ids.append(document_id)
                    cursor.execute("""
                        UPDATE iocs SET document_ids = ?, last_seen = ?
                        WHERE id = ?
                    """, (json.dumps(doc_ids), timestamp, existing['id']))
            else:
                # Insert new IOC
                cursor.execute("""
                    INSERT INTO iocs (value, type, confidence, first_seen, last_seen, document_ids, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (ioc['value'], ioc['type'], ioc.get('confidence', 0.8),
                     timestamp, timestamp, json.dumps([document_id]),
                     json.dumps(ioc.get('metadata', {}))))

        self.conn.commit()
        logger.info(f"Stored {len(iocs)} IOCs for document {document_id}")

    def store_ttps(self, ttps: List[Dict], document_id: int):
        """
        Store extracted TTPs in the database.

        Args:
            ttps: List of TTP dictionaries
            document_id: Associated document ID
        """
        cursor = self.conn.cursor()

        for ttp in ttps:
            cursor.execute("""
                INSERT INTO ttps (mitre_id, name, confidence, document_id, text_context)
                VALUES (?, ?, ?, ?, ?)
            """, (ttp['mitre_id'], ttp['name'], ttp.get('confidence', 0.8),
                 document_id, ttp.get('context', '')))

        self.conn.commit()
        logger.info(f"Stored {len(ttps)} TTPs for document {document_id}")

    def store_campaign(self, name: str, document_ids: List[int], 
                      ioc_ids: List[int], ttp_ids: List[int], 
                      confidence: float = 0.8, metadata: Dict = None) -> int:
        """
        Store a campaign cluster in the database.

        Args:
            name: Campaign name
            document_ids: List of associated document IDs
            ioc_ids: List of associated IOC IDs
            ttp_ids: List of associated TTP IDs
            confidence: Campaign confidence score
            metadata: Additional metadata

        Returns:
            Campaign ID
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO campaigns (name, confidence, document_ids, ioc_ids, ttp_ids, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, confidence, json.dumps(document_ids), json.dumps(ioc_ids),
             json.dumps(ttp_ids), timestamp, json.dumps(metadata or {})))

        campaign_id = cursor.lastrowid
        self.conn.commit()

        logger.info(f"Stored campaign {campaign_id}: {name}")
        return campaign_id

    def get_documents(self, limit: int = 100) -> List[Dict]:
        """Get documents from database."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM documents ORDER BY timestamp DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_iocs(self, limit: int = 100) -> List[Dict]:
        """Get iocs from database."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM iocs ORDER BY last_seen DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_iocs_by_document(self, document_id: int) -> List[Dict]:
        """Get IOCs associated with a document."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM iocs WHERE document_ids LIKE ?
        """, (f'%{document_id}%',))
        return [dict(row) for row in cursor.fetchall()]

    def get_ttps_by_document(self, document_id: int) -> List[Dict]:
        """Get TTPs associated with a document."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM ttps WHERE document_id = ?', (document_id,))
        return [dict(row) for row in cursor.fetchall()]

    def search_ioc(self, ioc_value: str) -> Optional[Dict]:
        """Search for a specific IOC."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM iocs WHERE value = ?', (ioc_value,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def semantic_search(self, query: str, top_k: int = 5) -> List[Tuple[int, float]]:
        """
        Perform semantic search on document embeddings.

        Args:
            query: Search query
            top_k: Number of results to return

        Returns:
            List of (document_id, similarity_score) tuples
        """
        query_embedding = self.embedder.encode([query])[0]
        query_embedding = query_embedding / np.linalg.norm(query_embedding)

        scores, indices = self.faiss_index.search(query_embedding.reshape(1, -1), top_k)

        # Map FAISS indices back to document IDs
        cursor = self.conn.cursor()
        cursor.execute('SELECT document_id FROM document_embeddings ORDER BY document_id')
        doc_id_mapping = [row[0] for row in cursor.fetchall()]

        results = []
        for i in range(len(indices[0])):
            if indices[0][i] < len(doc_id_mapping):
                doc_id = doc_id_mapping[indices[0][i]]
                similarity = float(scores[0][i])
                results.append((doc_id, similarity))

        return results

    def get_campaigns(self, limit: int = None) -> List[Dict]:
        """Get all campaigns."""
        cursor = self.conn.cursor()
        if limit:
            cursor.execute('SELECT * FROM campaigns ORDER BY created_at DESC LIMIT ?', (limit,))
        else:
            cursor.execute('SELECT * FROM campaigns ORDER BY created_at DESC')
        return [dict(row) for row in cursor.fetchall()]

    def get_document_by_id(self, doc_id: int) -> Optional[Dict]:
        """Get a document by ID."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM documents WHERE id = ?', (doc_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def delete_document(self, doc_id: int) -> bool:
        """
        Delete a document and clean up associated data.
        
        Args:
            doc_id: ID of the document to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            
            # 1. Delete from documents table
            cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
            if cursor.rowcount == 0:
                logger.warning(f"Document {doc_id} not found")
                return False
                
            # 2. Delete associated TTPs
            cursor.execute('DELETE FROM ttps WHERE document_id = ?', (doc_id,))
            
            # 3. Delete embedding
            cursor.execute('DELETE FROM document_embeddings WHERE document_id = ?', (doc_id,))
            
            # 4. Update IOCs
            # Get all IOCs that reference this document
            cursor.execute('SELECT id, document_ids FROM iocs WHERE document_ids LIKE ?', (f'%{doc_id}%',))
            iocs = cursor.fetchall()
            
            for ioc in iocs:
                doc_ids = json.loads(ioc['document_ids'])
                if doc_id in doc_ids:
                    doc_ids.remove(doc_id)
                    if not doc_ids:
                        # If no more documents reference this IOC, delete it
                        cursor.execute('DELETE FROM iocs WHERE id = ?', (ioc['id'],))
                    else:
                        # Update with remaining document IDs
                        cursor.execute('UPDATE iocs SET document_ids = ? WHERE id = ?', 
                                     (json.dumps(doc_ids), ioc['id']))
            
            self.conn.commit()
            
            # 5. Rebuild FAISS index
            # This is expensive but necessary to keep index in sync
            self._rebuild_faiss_index()
            
            logger.info(f"Successfully deleted document {doc_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting document {doc_id}: {e}")
            self.conn.rollback()
            return False

    def _rebuild_faiss_index(self):
        """Rebuild FAISS index from database embeddings."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT embedding FROM document_embeddings ORDER BY document_id')
            rows = cursor.fetchall()
            
            if not rows:
                self.faiss_index = faiss.IndexFlatIP(self.vector_dim)
                self.save_faiss_index()
                return

            embeddings = []
            for row in rows:
                emb = pickle.loads(row[0])
                embeddings.append(emb)
            
            embeddings_matrix = np.array(embeddings)
            # Normalize
            faiss.normalize_L2(embeddings_matrix)
            
            # Create new index
            self.faiss_index = faiss.IndexFlatIP(self.vector_dim)
            self.faiss_index.add(embeddings_matrix)
            self.save_faiss_index()
            
            logger.info("Rebuilt FAISS index")
            
        except Exception as e:
            logger.error(f"Error rebuilding FAISS index: {e}")

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
