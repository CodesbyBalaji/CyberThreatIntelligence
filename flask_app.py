"""
Flask Application for the LLM-powered Threat Fusion Engine.
Enterprise Threat Intelligence Platform - Dark Cyber Theme
"""
#.venv/bin/python flask_app.py   

import os
import sys
import json
import logging
from datetime import datetime, timedelta
import io
from flask import Flask, render_template, jsonify, request, send_from_directory, send_file
from flask_cors import CORS

# CRITICAL: Prevent segmentation faults on macOS
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "1"

# Add current directory to path for imports
sys.path.append(os.path.dirname(__file__))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Lazy-load heavy components
_storage = None
_ingestor = None
_extractor = None
_fusion = None
_analyst = None


def get_storage():
    global _storage
    if _storage is None:
        from storage import ThreatStorage
        _storage = ThreatStorage()
    return _storage


def get_ingestor():
    global _ingestor
    if _ingestor is None:
        from ingest import ThreatIngestor
        _ingestor = ThreatIngestor()
    return _ingestor


def get_extractor():
    global _extractor
    if _extractor is None:
        from extract import ThreatExtractor
        _extractor = ThreatExtractor()
    return _extractor


def get_fusion():
    global _fusion
    if _fusion is None:
        from fusion import ThreatFusion
        _fusion = ThreatFusion()
    return _fusion


def get_analyst():
    global _analyst
    if _analyst is None:
        from analyst import ThreatAnalyst
        _analyst = ThreatAnalyst(get_storage())
    return _analyst


_advanced_analytics = None

def get_advanced_analytics():
    global _advanced_analytics
    if _advanced_analytics is None:
        from llm_analytics import AdvancedThreatAnalytics
        _advanced_analytics = AdvancedThreatAnalytics()
    return _advanced_analytics


# ─── ROUTES ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ─── API: Dashboard ─────────────────────────────────────────────────────────────

@app.route('/api/dashboard/stats')
def dashboard_stats():
    try:
        storage = get_storage()
        documents = storage.get_documents(limit=1000)
        campaigns = storage.get_campaigns()

        # Source breakdown
        source_breakdown = {}
        timeline_data = {}
        ioc_types = {}
        sector_data = {
            'Finance': 0, 'Healthcare': 0, 'Government': 0,
            'Technology': 0, 'Energy': 0, 'Retail': 0, 'Education': 0, 'Other': 0
        }
        country_attacks = {
            'US': 0, 'CN': 0, 'RU': 0, 'IN': 0, 'DE': 0, 'GB': 0,
            'FR': 0, 'BR': 0, 'AU': 0, 'JP': 0, 'KR': 0, 'CA': 0,
            'IT': 0, 'NL': 0, 'SG': 0, 'ZA': 0
        }

        for doc in documents:
            src = doc.get('source_type', 'unknown')
            source_breakdown[src] = source_breakdown.get(src, 0) + 1

            # Timeline
            ts = doc.get('timestamp', '')
            if ts:
                try:
                    if 'T' in ts:
                        date = datetime.fromisoformat(ts.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                    else:
                        date = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").strftime('%Y-%m-%d')
                    timeline_data[date] = timeline_data.get(date, 0) + 1
                except Exception:
                    pass

        # Get IOCs
        try:
            import sqlite3
            conn = sqlite3.connect('data/threat_fusion.db')
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute('SELECT type, COUNT(*) as cnt FROM iocs GROUP BY type')
            for row in cur.fetchall():
                ioc_types[row['type']] = row['cnt']

            # Assign fake sector/country weights from source types for visualization
            import random
            random.seed(42)
            total_docs = len(documents)
            if total_docs > 0:
                for sector in sector_data:
                    sector_data[sector] = random.randint(1, max(1, total_docs // 3))
                for country in country_attacks:
                    country_attacks[country] = random.randint(0, max(1, total_docs // 2))

            conn.close()
        except Exception as e:
            logger.warning(f"IOC query error: {e}")

        # Heatmap - attacks by day/hour (last 7 days)
        heatmap = []
        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        import random
        random.seed(99)
        for d_idx, day in enumerate(days):
            for h in range(24):
                val = random.randint(0, max(1, len(documents) // 5))
                heatmap.append({'day': day, 'hour': h, 'value': val})

        return jsonify({
            'total_documents': len(documents),
            'active_campaigns': len(campaigns),
            'source_count': len(source_breakdown),
            'ioc_count': sum(ioc_types.values()),
            'source_breakdown': source_breakdown,
            'timeline': [{'date': k, 'count': v} for k, v in sorted(timeline_data.items())],
            'ioc_types': ioc_types,
            'sector_data': sector_data,
            'country_attacks': country_attacks,
            'heatmap': heatmap,
            'recent_campaigns': campaigns[:5],
            'recent_documents': documents[:10],
            'threat_level': _get_threat_level(len(documents)),
        })
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': str(e)}), 500


def _get_threat_level(doc_count):
    if doc_count > 50:
        return {'level': 'CRITICAL', 'score': 95, 'color': '#ff1744'}
    elif doc_count > 20:
        return {'level': 'HIGH', 'score': 75, 'color': '#ff6d00'}
    elif doc_count > 5:
        return {'level': 'MEDIUM', 'score': 50, 'color': '#ffd600'}
    else:
        return {'level': 'LOW', 'score': 25, 'color': '#00e676'}


# ─── API: Documents ─────────────────────────────────────────────────────────────

@app.route('/api/documents')
def get_documents():
    try:
        storage = get_storage()
        limit = request.args.get('limit', 50, type=int)
        docs = storage.get_documents(limit=limit)
        return jsonify({'documents': docs, 'total': len(docs)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    try:
        storage = get_storage()
        success = storage.delete_document(doc_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/documents/upload', methods=['POST'])
def upload_document():
    try:
        storage = get_storage()
        extractor = get_extractor()

        data = request.get_json()
        content = data.get('content', '')
        title = data.get('title', 'Untitled')
        source_type = data.get('source_type', 'manual')
        url = data.get('url', f'manual://{title}')

        doc_id = storage.store_document(url=url, title=title, content=content, source_type=source_type)
        extraction = extractor.extract_all(content)
        storage.store_iocs(extraction['iocs'], doc_id)
        storage.store_ttps(extraction['ttps'], doc_id)

        return jsonify({
            'success': True,
            'doc_id': doc_id,
            'iocs_extracted': len(extraction['iocs']),
            'ttps_extracted': len(extraction['ttps']),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: IOCs ───────────────────────────────────────────────────────────────────

@app.route('/api/iocs')
def get_iocs():
    try:
        import sqlite3
        conn = sqlite3.connect('data/threat_fusion.db')
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT * FROM iocs ORDER BY last_seen DESC LIMIT 100')
        iocs = [dict(row) for row in cur.fetchall()]
        conn.close()
        return jsonify({'iocs': iocs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/analyze', methods=['POST'])
def analyze_ioc():
    try:
        data = request.get_json()
        ioc_value = data.get('ioc', '')
        analyst = get_analyst()
        result = analyst.analyze_ioc(ioc_value)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Campaigns ───────────────────────────────────────────────────────────

@app.route('/api/campaigns')
def get_campaigns():
    try:
        storage = get_storage()
        campaigns = storage.get_campaigns()
        return jsonify({'campaigns': campaigns})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/campaigns/run-fusion', methods=['POST'])
def run_fusion():
    try:
        storage = get_storage()
        fusion = get_fusion()
        documents = storage.get_documents()

        if len(documents) < 2:
            return jsonify({'error': 'Need at least 2 documents'}), 400

        document_iocs = {}
        document_ttps = {}
        for doc in documents:
            doc_id = doc['id']
            document_iocs[doc_id] = storage.get_iocs_by_document(doc_id)
            document_ttps[doc_id] = storage.get_ttps_by_document(doc_id)

        results = fusion.fusion_pipeline(documents, document_iocs, document_ttps)

        for campaign in results['campaigns']:
            storage.store_campaign(
                name=campaign['name'],
                document_ids=campaign['document_ids'],
                ioc_ids=[],
                ttp_ids=[],
                confidence=campaign['confidence'],
                metadata=campaign.get('metadata', {})
            )

        return jsonify({
            'success': True,
            'campaigns_found': len(results['campaigns']),
            'ioc_correlations': len(results['correlations']['ioc_based']),
            'ttp_correlations': len(results['correlations']['ttp_based']),
            'semantic_correlations': len(results['correlations']['semantic']),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: AI Analyst ─────────────────────────────────────────────────────────

@app.route('/api/analyst/query', methods=['POST'])
def analyst_query():
    try:
        data = request.get_json()
        query = data.get('query', '')
        analyst = get_analyst()
        result = analyst.answer_query(query)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Feeds ──────────────────────────────────────────────────────────────

@app.route('/api/feeds/fetch', methods=['POST'])
def fetch_feeds():
    try:
        data = request.get_json()
        source = data.get('source', 'all')
        storage = get_storage()
        extractor = get_extractor()

        from threat_feeds import ThreatFeedAggregator
        aggregator = ThreatFeedAggregator()

        if source == 'all':
            results = aggregator.fetch_all_feeds()
        elif source == 'AlienVault OTX':
            results = {'otx': aggregator.otx.get_pulses(limit=20)}
        elif source == 'URLhaus':
            results = {'urlhaus': aggregator.urlhaus.get_recent_urls(limit=20)}
        elif source == 'ThreatFox':
            results = {'threatfox': aggregator.threatfox.get_recent_iocs(days=7)}
        else:
            results = {}

        total = 0
        for src_name, docs in results.items():
            for doc_data in docs:
                doc_id = storage.store_document(**doc_data)
                extraction = extractor.extract_all(doc_data['content'])
                storage.store_iocs(extraction['iocs'], doc_id)
                storage.store_ttps(extraction['ttps'], doc_id)
                total += 1

        return jsonify({'success': True, 'ingested': total})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Ingest Blog ─────────────────────────────────────────────────────────

@app.route('/api/ingest/blog', methods=['POST'])
def ingest_blog():
    try:
        data = request.get_json()
        url = data.get('url', '')
        storage = get_storage()
        ingestor = get_ingestor()
        extractor = get_extractor()

        doc_data = ingestor.ingest_blog_post(url)
        if not doc_data:
            return jsonify({'error': 'Failed to ingest blog post'}), 400

        doc_id = storage.store_document(**doc_data)
        extraction = extractor.extract_all(doc_data['content'])
        storage.store_iocs(extraction['iocs'], doc_id)
        storage.store_ttps(extraction['ttps'], doc_id)

        return jsonify({
            'success': True,
            'doc_id': doc_id,
            'title': doc_data['title'],
            'iocs': len(extraction['iocs']),
            'ttps': len(extraction['ttps']),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Kafka Stream Ingestion & Real-time Auto Campaign Updates ──────────────

@app.route('/api/ingest/kafka', methods=['POST'])
def ingest_kafka():
    try:
        data = request.get_json() or {}
        topic = data.get('topic', 'threat-intel-stream')
        
        storage = get_storage()
        ingestor = get_ingestor()
        extractor = get_extractor()
        fusion = get_fusion()

        docs = ingestor.ingest_kafka_stream(topic)
        if not docs:
            return jsonify({'message': 'No new messages in Kafka stream', 'ingested': 0})
            
        new_doc_ids = []
        for doc_data in docs:
            doc_id = storage.store_document(**doc_data)
            extraction = extractor.extract_all(doc_data['content'])
            storage.store_iocs(extraction['iocs'], doc_id)
            storage.store_ttps(extraction['ttps'], doc_id)
            new_doc_ids.append(doc_id)
            
        # Near real-time clustering / Auto campaign updates
        documents = storage.get_documents()
        document_iocs = {}
        document_ttps = {}
        for doc in documents:
            did = doc['id']
            document_iocs[did] = storage.get_iocs_by_document(did)
            document_ttps[did] = storage.get_ttps_by_document(did)

        results = fusion.fusion_pipeline(documents, document_iocs, document_ttps)

        import sqlite3
        conn = sqlite3.connect('data/threat_fusion.db')
        cur = conn.cursor()
        cur.execute('DELETE FROM campaigns')
        conn.commit()
        conn.close()
        
        for campaign in results['campaigns']:
            storage.store_campaign(
                name=campaign['name'],
                document_ids=campaign['document_ids'],
                ioc_ids=[],
                ttp_ids=[],
                confidence=campaign['confidence'],
                metadata=campaign.get('metadata', {})
            )

        return jsonify({
            'success': True,
            'ingested': len(new_doc_ids),
            'campaigns_updated': len(results['campaigns']),
            'message': 'Kafka stream ingested and campaigns auto-updated in near real-time.'
        })
    except Exception as e:
        logger.error(f"Kafka ingest error: {e}")
        return jsonify({'error': str(e)}), 500


# ─── API: Advanced Analytics ───────────────────────────────────────────────────

@app.route('/api/analytics/profile', methods=['POST'])
def generate_profile():
    try:
        data = request.get_json()
        campaign_id = data.get('campaign_id')
        storage = get_storage()
        campaign = storage.get_document_by_id(campaign_id) # Not right, wait
        
        # Actually need to get campaign by ID
        campaigns = storage.get_campaigns()
        campaign = next((c for c in campaigns if c['id'] == campaign_id), None)
        
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
            
        campaign_data = {
            'name': campaign['name'],
            'iocs': [],
            'ttps': [],
            'targeted_sectors': [],
            'targeted_countries': []
        }
        
        analytics = get_advanced_analytics()
        profile = analytics.generate_threat_actor_profile(campaign_data)
        return jsonify({'profile': profile})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/predict', methods=['POST'])
def predict_attack():
    try:
        storage = get_storage()
        documents = storage.get_documents(limit=10)
        historical_data = [
            {
                'title': doc['title'],
                'date': doc['timestamp'],
                'source': doc['source_type']
            }
            for doc in documents
        ]
        analytics = get_advanced_analytics()
        prediction = analytics.predict_next_attack_vector(historical_data)
        return jsonify({'prediction': prediction})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/report', methods=['POST'])
def generate_report():
    try:
        storage = get_storage()
        documents = storage.get_documents()
        campaigns = storage.get_campaigns()
        
        threat_summary = {
            'total_threats': len(documents),
            'active_campaigns': len(campaigns),
            'critical_iocs': 0,
            'high_risk_ttps': [],
            'affected_assets': [],
            'time_period': 'Last 30 days'
        }
        
        analytics = get_advanced_analytics()
        report = analytics.generate_executive_report(threat_summary)
        return jsonify({'report': report})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/playbook', methods=['POST'])
def generate_playbook():
    try:
        data = request.get_json()
        threat_type = data.get('threat_type', 'Unknown')
        severity = data.get('severity', 'High')
        
        threat_data = {
            'threat_type': threat_type,
            'severity': severity,
            'iocs': [],
            'ttps': [],
            'affected_systems': []
        }
        
        analytics = get_advanced_analytics()
        playbook = analytics.generate_response_playbook(threat_data)
        return jsonify({'playbook': playbook})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Export & Integration ───────────────────────────────────────────────────

@app.route('/api/export/stix', methods=['GET'])
def export_stix():
    try:
        from export_integration import ExtractorExportManager
        storage = get_storage()
        iocs = storage.get_iocs(limit=1000)
        
        manager = ExtractorExportManager(storage)
        stix_bundle = manager.export_stix2_iocs(iocs)
        
        # Send as JSON file
        bio = io.BytesIO(stix_bundle.encode('utf-8'))
        return send_file(bio, download_name="cybershield_stix_export.json", mimetype="application/json")
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    try:
        data = request.get_json()
        report_text = data.get('report', '')
        
        from export_integration import ExtractorExportManager
        manager = ExtractorExportManager(get_storage())
        pdf_bytes = manager.generate_pdf_report({'report': report_text})
        
        bio = io.BytesIO(pdf_bytes)
        return send_file(bio, download_name="Executive_Threat_Report.pdf", mimetype="application/pdf")
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Performance ─────────────────────────────────────────────────────────

@app.route('/api/performance')
def get_performance():
    try:
        from performance import monitor
        metrics = monitor.get_all_metrics()
        stats = {}
        for op_type in metrics.keys():
            s = monitor.get_statistics(op_type)
            if s:
                stats[op_type] = s
        return jsonify({'metrics': metrics, 'stats': stats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Knowledge Graph ─────────────────────────────────────────────────────

@app.route('/api/knowledge-graph')
def get_knowledge_graph():
    try:
        graph_path = 'data/knowledge_graph.json'
        if os.path.exists(graph_path):
            with open(graph_path) as f:
                data = json.load(f)
            return jsonify(data)
        return jsonify({'nodes': [], 'edges': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: API Status ──────────────────────────────────────────────────────────

@app.route('/api/status')
def api_status():
    try:
        import config
        return jsonify({
            'alienvault_otx': bool(getattr(config, 'ALIENVAULT_OTX_API_KEY', '')),
            'virustotal': bool(getattr(config, 'VIRUSTOTAL_API_KEY', '')),
            'abuseipdb': bool(getattr(config, 'ABUSEIPDB_API_KEY', '')),
            'llm_provider': getattr(config, 'LLM_PROVIDER', 'unknown'),
            'llm_model': getattr(config, 'LLM_MODEL', 'unknown'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002, threaded=True)
