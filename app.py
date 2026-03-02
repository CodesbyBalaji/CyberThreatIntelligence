"""
Main Streamlit application for the LLM-powered Threat Fusion Engine.
Provides a dashboard for threat intelligence analysis and querying.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import os
import sys

# CRITICAL: Prevent segmentation faults on macOS
# These environment variables MUST be set before importing sentence_transformers
# to avoid threading conflicts that cause crashes during encoding
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "1"

# Add current directory to path for imports
sys.path.append(os.path.dirname(__file__))

from storage import ThreatStorage
from ingest import ThreatIngestor
from extract import ThreatExtractor
from fusion import ThreatFusion
from analyst import ThreatAnalyst

# Page configuration
st.set_page_config(
    page_title="🛡️ Advanced CTI Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load CSS from external file to avoid caching issues
def load_css():
    css_file = os.path.join(os.path.dirname(__file__), 'style.css')
    with open(css_file) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

try:
    load_css()
except Exception as e:
    st.error(f"CSS loading error: {e}")
    # Fallback inline CSS for visibility
    st.markdown("""
    <style>
        .main { background-color: #f8f9fa !important; }
        .block-container { background: white !important; }
        h1, h2, h3, p, span, div { color: #2d3748 !important; }
        section[data-testid="stSidebar"] { background: #2d3748 !important; }
        section[data-testid="stSidebar"] * { color: white !important; }
    </style>
    """, unsafe_allow_html=True)

@st.cache_resource
def initialize_components():
    """Initialize all system components."""
    storage = ThreatStorage()
    ingestor = ThreatIngestor()
    extractor = ThreatExtractor()
    fusion = ThreatFusion()
    analyst = ThreatAnalyst(storage)

    return storage, ingestor, extractor, fusion, analyst

def main():
    """Main application function."""

    # Initialize components
    storage, ingestor, extractor, fusion, analyst = initialize_components()

    # Enhanced Main header with subtitle
    st.markdown('''
    <h1 class="main-header">🛡️ Cyber Threat Intelligence Using LLMs</h1>
    <p style="text-align: center; color: #667eea; font-size: 1.2rem; margin-top: -1.5rem; margin-bottom: 2rem;">
        Cyber Threat Intelligence Using LLMs
    </p>
    ''', unsafe_allow_html=True)

    # Sidebar navigation with enhanced styling
    st.sidebar.markdown("### 🎯 Navigation")
    
    # Show API status in sidebar
    import config
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔑 API Status")
    
    api_status = {
        "AlienVault OTX": "✅" if config.ALIENVAULT_OTX_API_KEY else "❌",
        "VirusTotal": "✅" if config.VIRUSTOTAL_API_KEY else "❌",
        "AbuseIPDB": "✅" if config.ABUSEIPDB_API_KEY else "❌",
    }
    
    for api, status in api_status.items():
        st.sidebar.markdown(f"{status} {api}")
    
    st.sidebar.markdown("---")
    
    page = st.sidebar.selectbox(
        "Select Page",
        ["🏠 Dashboard", "📥 Real-Time Feeds", "📄 Data Ingestion", "🔍 IOC/TTP Analysis", 
         "🔗 Campaign Analysis", "🤖 AI Analyst", "🧠 Advanced Analytics", "🕸️ Knowledge Graph", "⚡ Performance"]
    )

    # Page routing
    if page == "🏠 Dashboard":
        show_dashboard(storage, analyst)
    elif page == "📥 Real-Time Feeds":
        show_realtime_feeds_page(storage, extractor)
    elif page == "📄 Data Ingestion":
        show_ingestion_page(storage, ingestor, extractor)
    elif page == "🔍 IOC/TTP Analysis":
        show_extraction_page(storage, extractor)
    elif page == "🔗 Campaign Analysis":
        show_fusion_page(storage, fusion)
    elif page == "🤖 AI Analyst":
        show_analyst_page(analyst)
    elif page == "🧠 Advanced Analytics":
        show_advanced_analytics_page(storage)
    elif page == "🕸️ Knowledge Graph":
        show_knowledge_graph_page(storage, fusion)
    elif page == "⚡ Performance":
        show_performance_page()

def show_dashboard(storage, analyst):
    """Display the main dashboard."""

    st.header("📊 Threat Intelligence Dashboard")

    # Get summary data
    documents = storage.get_documents(limit=100)
    campaigns = storage.get_campaigns()
    threat_summary = analyst.get_threat_summary()

    # Metrics row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Documents", len(documents))
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Active Campaigns", len(campaigns))
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        source_breakdown = threat_summary.get('source_breakdown', {})
        total_sources = sum(source_breakdown.values())
        st.metric("Data Sources", len(source_breakdown))
        st.markdown('</div>', unsafe_allow_html=True)

    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Analysis Period", f"{threat_summary['time_period_days']} days")
        st.markdown('</div>', unsafe_allow_html=True)

    # Charts row
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📈 Document Sources")
        if source_breakdown:
            df_sources = pd.DataFrame(list(source_breakdown.items()), columns=['Source', 'Count'])
            fig_pie = px.pie(df_sources, values='Count', names='Source', title="Document Sources Distribution")
            fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No data available for source breakdown.")

    with col2:
        st.subheader("🕐 Document Timeline")
        if documents:
            # Create timeline data
            timeline_data = []
            for doc in documents:
                if doc.get('timestamp'):
                    try:
                        # Handle various timestamp formats
                        ts = doc['timestamp']
                        if 'T' in ts:
                            date = datetime.fromisoformat(ts.replace('Z', '+00:00')).date()
                        else:
                            date = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").date()
                        timeline_data.append(date)
                    except Exception as e:
                        pass

            if timeline_data:
                df_timeline = pd.DataFrame(timeline_data, columns=['Date'])
                df_timeline['Count'] = 1
                df_grouped = df_timeline.groupby('Date').count().reset_index()

                fig_line = px.line(df_grouped, x='Date', y='Count', title="Documents Over Time")
                fig_line.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig_line, use_container_width=True)
            else:
                st.info("No timeline data available.")
        else:
            st.info("No documents found.")

    # Recent campaigns
    st.subheader("🎯 Recent Campaigns")
    if campaigns:
        campaign_df = pd.DataFrame(campaigns[:10])  # Show top 10
        
        # Handle timestamp conversion safely
        if 'created_at' in campaign_df.columns:
            campaign_df['created_at'] = pd.to_datetime(campaign_df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
        
        # Select only available columns
        available_cols = []
        col_config = {}
        
        if 'name' in campaign_df.columns:
            available_cols.append('name')
            col_config['name'] = "Campaign Name"
        
        if 'confidence' in campaign_df.columns:
            available_cols.append('confidence')
            col_config['confidence'] = st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1)
        
        # Check for document_count or similar columns
        doc_count_col = None
        for col in ['document_count', 'doc_count', 'documents']:
            if col in campaign_df.columns:
                doc_count_col = col
                break
        
        if doc_count_col:
            available_cols.append(doc_count_col)
            col_config[doc_count_col] = "Documents"
        
        if 'created_at' in campaign_df.columns:
            available_cols.append('created_at')
            col_config['created_at'] = "Created"
        
        if available_cols:
            st.dataframe(
                campaign_df[available_cols],
                column_config=col_config,
                use_container_width=True
            )
        else:
            st.dataframe(campaign_df, use_container_width=True)
    else:
        st.info("No campaigns identified yet. Ingest more data to enable campaign detection.")

    # Recent documents
    st.subheader("📄 Recent Documents")
    if documents:
        doc_df = pd.DataFrame(documents[:20])  # Show top 20
        doc_df['timestamp'] = pd.to_datetime(doc_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')

        st.dataframe(
            doc_df[['title', 'source_type', 'timestamp']],
            column_config={
                "title": "Document Title",
                "source_type": "Source Type", 
                "timestamp": "Ingested"
            },
            use_container_width=True
        )

def show_ingestion_page(storage, ingestor, extractor):
    """Display the data ingestion page."""

    st.header("📥 Data Ingestion")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Manual Upload", "Blog Ingestion", "OSINT Feeds", "Sample Data", "Manage Data"])

    with tab1:
        st.subheader("Manual File Upload")

        uploaded_file = st.file_uploader(
            "Upload a text file or document",
            type=['txt', 'md', 'json'],
            help="Upload threat intelligence documents for analysis"
        )

        if uploaded_file is not None:
            content = uploaded_file.read().decode('utf-8')

            col1, col2 = st.columns(2)
            with col1:
                source_type = st.selectbox("Source Type", ["manual", "blog", "osint", "darkweb"])
            with col2:
                title = st.text_input("Document Title", value=uploaded_file.name)

            if st.button("Process Document"):
                with st.spinner("Processing document..."):
                    # Store document
                    doc_id = storage.store_document(
                        url=f"file://{uploaded_file.name}",
                        title=title,
                        content=content,
                        source_type=source_type
                    )

                    # Extract IOCs and TTPs
                    extraction_result = extractor.extract_all(content)

                    # Store extractions
                    storage.store_iocs(extraction_result['iocs'], doc_id)
                    storage.store_ttps(extraction_result['ttps'], doc_id)

                    st.success(f"Document processed successfully! Document ID: {doc_id}")

                    # Show extraction results
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("IOCs Extracted", len(extraction_result['iocs']))
                    with col2:
                        st.metric("TTPs Extracted", len(extraction_result['ttps']))

                    if extraction_result['iocs']:
                        st.subheader("Extracted IOCs")
                        ioc_df = pd.DataFrame(extraction_result['iocs'])
                        st.dataframe(ioc_df[['value', 'type', 'confidence']])

                    if extraction_result['ttps']:
                        st.subheader("Extracted TTPs")
                        ttp_df = pd.DataFrame(extraction_result['ttps'])
                        st.dataframe(ttp_df[['mitre_id', 'name', 'confidence']])

    with tab2:
        st.subheader("Security Blog Ingestion")

        blog_url = st.text_input("Enter blog post URL:")

        if st.button("Ingest Blog Post"):
            if blog_url:
                with st.spinner("Ingesting blog post..."):
                    doc_data = ingestor.ingest_blog_post(blog_url)

                    if doc_data:
                        doc_id = storage.store_document(**doc_data)
                        extraction_result = extractor.extract_all(doc_data['content'])

                        storage.store_iocs(extraction_result['iocs'], doc_id)
                        storage.store_ttps(extraction_result['ttps'], doc_id)

                        st.success("Blog post ingested successfully!")
                        st.json(extraction_result)
                    else:
                        st.error("Failed to ingest blog post. Please check the URL.")

    with tab3:
        st.subheader("OSINT Feed Ingestion")

        col1, col2 = st.columns(2)
        with col1:
            feed_type = st.selectbox("Feed Type", ["alientvault_otx", "abuse_ch"])
        with col2:
            if st.button("Ingest Feed"):
                with st.spinner("Ingesting OSINT feed..."):
                    documents = ingestor.ingest_osint_feed(feed_type)

                    processed_count = 0
                    for doc_data in documents:
                        doc_id = storage.store_document(**doc_data)
                        extraction_result = extractor.extract_all(doc_data['content'])

                        storage.store_iocs(extraction_result['iocs'], doc_id)
                        storage.store_ttps(extraction_result['ttps'], doc_id)
                        processed_count += 1

                    st.success(f"Processed {processed_count} documents from {feed_type} feed")

    with tab4:
        st.subheader("Load Sample Data")
        st.info("Load pre-configured sample data for demonstration purposes.")

        if st.button("Load All Sample Data"):
            with st.spinner("Loading sample data..."):
                sample_count = load_sample_data(storage, ingestor, extractor)
                st.success(f"Loaded {sample_count} sample documents!")

    with tab5:
        st.subheader("Manage Data")
        
        # Get all documents
        documents = storage.get_documents(limit=1000)
        
        if not documents:
            st.info("No documents found.")
        else:
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"Total Documents: {len(documents)}")
            
            # Create a dataframe for display
            doc_df = pd.DataFrame(documents)
            doc_df['timestamp'] = pd.to_datetime(doc_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
            
            # Add a selection column
            doc_df['Select'] = False
            
            # Reorder columns
            display_df = doc_df[['Select', 'id', 'title', 'source_type', 'timestamp']]
            
            # Use data_editor for selection
            edited_df = st.data_editor(
                display_df,
                column_config={
                    "Select": st.column_config.CheckboxColumn(
                        "Select",
                        help="Select documents to delete",
                        default=False,
                    ),
                    "id": "ID",
                    "title": "Title",
                    "source_type": "Source",
                    "timestamp": "Date"
                },
                disabled=["id", "title", "source_type", "timestamp"],
                hide_index=True,
                use_container_width=True
            )
            
            # Get selected IDs
            selected_rows = edited_df[edited_df['Select']]
            selected_ids = selected_rows['id'].tolist()
            
            with col2:
                if selected_ids:
                    if st.button(f"🗑️ Delete ({len(selected_ids)})", type="primary"):
                        with st.spinner(f"Deleting {len(selected_ids)} documents..."):
                            success_count = 0
                            for doc_id in selected_ids:
                                if storage.delete_document(doc_id):
                                    success_count += 1
                            
                            if success_count == len(selected_ids):
                                st.success(f"Successfully deleted {success_count} documents!")
                            else:
                                st.warning(f"Deleted {success_count} out of {len(selected_ids)} documents.")
                            
                            st.rerun()

def show_extraction_page(storage, extractor):
    """Display IOC and TTP extraction analysis page."""

    st.header("🔍 IOC & TTP Analysis")

    # Get documents
    documents = storage.get_documents()

    if not documents:
        st.warning("No documents available. Please ingest some data first.")
        return

    # Document selection
    doc_options = {f"{doc['title'][:50]}... (ID: {doc['id']})": doc['id'] for doc in documents[:20]}
    selected_doc_key = st.selectbox("Select Document for Analysis", list(doc_options.keys()))
    selected_doc_id = doc_options[selected_doc_key]

    if st.button("Analyze Selected Document"):
        doc = storage.get_document_by_id(selected_doc_id)

        if doc:
            with st.spinner("Extracting IOCs and TTPs..."):
                extraction_result = extractor.extract_all(doc['content'])

                # Update database with new extractions
                storage.store_iocs(extraction_result['iocs'], selected_doc_id)
                storage.store_ttps(extraction_result['ttps'], selected_doc_id)

            # Display results
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("🎯 Extracted IOCs")
                if extraction_result['iocs']:
                    ioc_df = pd.DataFrame(extraction_result['iocs'])
                    st.dataframe(
                        ioc_df[['value', 'type', 'confidence']],
                        column_config={
                            "value": "IOC Value",
                            "type": "Type",
                            "confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1)
                        }
                    )
                else:
                    st.info("No IOCs extracted from this document.")

            with col2:
                st.subheader("⚔️ Extracted TTPs")
                if extraction_result['ttps']:
                    ttp_df = pd.DataFrame(extraction_result['ttps'])
                    st.dataframe(
                        ttp_df[['mitre_id', 'name', 'confidence']],
                        column_config={
                            "mitre_id": "MITRE ID",
                            "name": "Technique Name",
                            "confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1)
                        }
                    )
                else:
                    st.info("No TTPs extracted from this document.")

            # Summary
            st.subheader("📋 Extraction Summary")
            st.text_area("Summary", extraction_result.get('summary', 'No summary available'), height=100)

def show_fusion_page(storage, fusion):
    """Display campaign analysis and fusion page."""

    st.header("🔗 Campaign Analysis & Fusion")

    documents = storage.get_documents()

    if len(documents) < 2:
        st.warning("Need at least 2 documents to perform correlation analysis.")
        return

    if st.button("Run Fusion Analysis"):
        with st.spinner("Running fusion analysis..."):
            # Get document IOCs and TTPs
            document_iocs = {}
            document_ttps = {}

            for doc in documents:
                doc_id = doc['id']
                document_iocs[doc_id] = storage.get_iocs_by_document(doc_id)
                document_ttps[doc_id] = storage.get_ttps_by_document(doc_id)

            # Run fusion pipeline
            fusion_results = fusion.fusion_pipeline(documents, document_iocs, document_ttps)

            # Store campaigns
            for campaign in fusion_results['campaigns']:
                storage.store_campaign(
                    name=campaign['name'],
                    document_ids=campaign['document_ids'],
                    ioc_ids=[],  # Would need to map IOCs to IDs
                    ttp_ids=[],  # Would need to map TTPs to IDs
                    confidence=campaign['confidence'],
                    metadata=campaign.get('metadata', {})
                )

        # Display results
        st.success("Fusion analysis completed!")

        # Correlation statistics
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("IOC Correlations", len(fusion_results['correlations']['ioc_based']))
        with col2:
            st.metric("TTP Correlations", len(fusion_results['correlations']['ttp_based']))
        with col3:
            st.metric("Semantic Correlations", len(fusion_results['correlations']['semantic']))

        # Campaign results
        st.subheader("🎯 Detected Campaigns")
        if fusion_results['campaigns']:
            campaign_df = pd.DataFrame(fusion_results['campaigns'])
            st.dataframe(
                campaign_df[['name', 'confidence', 'document_count']],
                column_config={
                    "name": "Campaign Name",
                    "confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1),
                    "document_count": "Documents"
                }
            )
        else:
            st.info("No campaigns detected with current correlation thresholds.")

        # Knowledge graph statistics
        st.subheader("📊 Knowledge Graph")
        kg_stats = fusion_results['knowledge_graph_stats']
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Graph Nodes", kg_stats['nodes'])
        with col2:
            st.metric("Graph Edges", kg_stats['edges'])

def show_analyst_page(analyst):
    """Display the analyst query page."""

    st.header("🤖 AI Threat Analyst")

    tab1, tab2, tab3 = st.tabs(["Natural Language Query", "IOC Analysis", "Campaign Deep Dive"])

    with tab1:
        st.subheader("Ask the AI Analyst")

        query = st.text_area(
            "Enter your threat intelligence query:",
            placeholder="e.g., What do we know about domain malicious-site.com?",
            height=100
        )

        if st.button("Submit Query") and query:
            with st.spinner("Analyzing threat intelligence..."):
                result = analyst.answer_query(query)

            if result['found_evidence']:
                st.subheader("🎯 Analysis Results")
                st.markdown(result['llm_response'])

                st.subheader("📚 Supporting Evidence")
                for i, evidence in enumerate(result['evidence_snippets'], 1):
                    with st.expander(f"Evidence {i}: {evidence['title']}"):
                        st.write(f"**Similarity Score:** {evidence['similarity']:.2f}")
                        st.write(f"**Source Type:** {evidence['source_type']}")
                        st.write(evidence['snippet'])
            else:
                st.warning(result['message'])

    with tab2:
        st.subheader("IOC Deep Analysis")

        ioc_value = st.text_input("Enter IOC to analyze:", placeholder="e.g., malicious-domain.com")

        if st.button("Analyze IOC") and ioc_value:
            with st.spinner("Analyzing IOC..."):
                result = analyst.analyze_ioc(ioc_value)

            if result['found']:
                st.subheader(f"🎯 Analysis for {ioc_value}")
                st.markdown(result['llm_analysis'])

                # IOC metadata
                st.subheader("📊 IOC Metadata")
                ioc_data = result['ioc_data']
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Type", ioc_data['type'])
                with col2:
                    st.metric("Confidence", f"{ioc_data['confidence']:.2f}")
                with col3:
                    st.metric("Documents", len(result['evidence_snippets']))

                # Investigation suggestions
                suggestions = analyst.suggest_investigations(result)
                if suggestions:
                    st.subheader("💡 Investigation Suggestions")
                    for suggestion in suggestions:
                        st.write(f"• {suggestion}")
            else:
                st.warning(result['message'])

    with tab3:
        st.subheader("Campaign Analysis")

        campaigns = analyst.storage.get_campaigns()

        if campaigns:
            campaign_options = {f"{camp['name']} (ID: {camp['id']})": camp['id'] for camp in campaigns}
            selected_campaign_key = st.selectbox("Select Campaign", list(campaign_options.keys()))
            selected_campaign_id = campaign_options[selected_campaign_key]

            if st.button("Analyze Campaign"):
                with st.spinner("Analyzing campaign..."):
                    result = analyst.analyze_campaign(selected_campaign_id)

                if result['found']:
                    st.subheader(f"🎯 Campaign Analysis: {result['campaign_data']['name']}")
                    st.markdown(result['llm_analysis'])

                    # Campaign statistics
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Documents", result['document_count'])
                    with col2:
                        st.metric("IOCs", result['ioc_count'])
                    with col3:
                        st.metric("TTPs", result['ttp_count'])
                else:
                    st.error(result['message'])
        else:
            st.info("No campaigns available. Run fusion analysis first.")

def show_knowledge_graph_page(storage, fusion):
    """Display knowledge graph visualization."""

    st.header("🕸️ Knowledge Graph")

    st.info("Knowledge graph functionality requires additional visualization libraries. "
            "The graph data is stored in JSON format and can be visualized with external tools.")

    # Load and display graph statistics
    try:
        if os.path.exists("data/knowledge_graph.json"):
            with open("data/knowledge_graph.json", 'r') as f:
                graph_data = json.load(f)

            nodes = graph_data.get('nodes', [])
            edges = graph_data.get('edges', [])

            st.subheader("📊 Graph Statistics")
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Total Nodes", len(nodes))

            with col2:
                st.metric("Total Edges", len(edges))

            with col3:
                # Count node types
                node_types = {}
                for node in nodes:
                    node_type = node.get('type', 'unknown')
                    node_types[node_type] = node_types.get(node_type, 0) + 1
                st.metric("Node Types", len(node_types))

            # Node type distribution
            if node_types:
                st.subheader("📈 Node Type Distribution")
                df_nodes = pd.DataFrame(list(node_types.items()), columns=['Type', 'Count'])
                fig = px.bar(df_nodes, x='Type', y='Count', title="Knowledge Graph Node Types")
                st.plotly_chart(fig, use_container_width=True)

            # Sample nodes
            st.subheader("🔍 Sample Nodes")
            if nodes:
                sample_nodes = nodes[:10]  # Show first 10 nodes
                df_sample = pd.DataFrame(sample_nodes)
                st.dataframe(df_sample)

        else:
            st.warning("No knowledge graph found. Run fusion analysis to generate the graph.")

    except Exception as e:
        st.error(f"Error loading knowledge graph: {str(e)}")

def load_sample_data(storage, ingestor, extractor):
    """Load sample data for demonstration."""

    sample_count = 0

    # Load blog samples
    try:
        blog_file = "data/blogs/sample_blogs.json"
        if os.path.exists(blog_file):
            with open(blog_file, 'r') as f:
                blog_samples = json.load(f)

            for blog in blog_samples:
                doc_id = storage.store_document(
                    url=blog['url'],
                    title=blog['title'], 
                    content=blog['content'],
                    source_type='blog',
                    metadata=blog['metadata']
                )

                extraction_result = extractor.extract_all(blog['content'])
                storage.store_iocs(extraction_result['iocs'], doc_id)
                storage.store_ttps(extraction_result['ttps'], doc_id)
                sample_count += 1
    except Exception as e:
        st.error(f"Error loading blog samples: {str(e)}")

    # Load OSINT samples
    try:
        osint_documents = ingestor.ingest_osint_feed('alientvault_otx')
        for doc_data in osint_documents:
            doc_id = storage.store_document(**doc_data)
            extraction_result = extractor.extract_all(doc_data['content'])
            storage.store_iocs(extraction_result['iocs'], doc_id)
            storage.store_ttps(extraction_result['ttps'], doc_id)
            sample_count += 1
    except Exception as e:
        st.error(f"Error loading OSINT samples: {str(e)}")

    # Load dark web samples  
    try:
        darkweb_documents = ingestor.ingest_darkweb_posts('data/darkweb')
        for doc_data in darkweb_documents:
            doc_id = storage.store_document(**doc_data)
            extraction_result = extractor.extract_all(doc_data['content'])
            storage.store_iocs(extraction_result['iocs'], doc_id)
            storage.store_ttps(extraction_result['ttps'], doc_id)
            sample_count += 1
    except Exception as e:
        st.error(f"Error loading dark web samples: {str(e)}")

    return sample_count

def show_realtime_feeds_page(storage, extractor):
    """Display real-time threat intelligence feeds page."""
    
    st.header("📥 Real-Time Threat Intelligence Feeds")
    
    st.markdown("""
    <div class="info-card">
        <h3>🌐 Live Threat Feeds</h3>
        <p>Ingest real-time threat intelligence from multiple sources including AlienVault OTX, URLhaus, and ThreatFox.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Import threat feeds module
    try:
        from threat_feeds import ThreatFeedAggregator
        
        aggregator = ThreatFeedAggregator()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🔄 Fetch All Feeds")
            if st.button("🚀 Fetch from All Sources", use_container_width=True):
                with st.spinner("Fetching threat intelligence from all sources..."):
                    try:
                        results = aggregator.fetch_all_feeds()
                        
                        total_docs = 0
                        for source, docs in results.items():
                            for doc_data in docs:
                                doc_id = storage.store_document(**doc_data)
                                extraction_result = extractor.extract_all(doc_data['content'])
                                storage.store_iocs(extraction_result['iocs'], doc_id)
                                storage.store_ttps(extraction_result['ttps'], doc_id)
                                total_docs += 1
                        
                        st.success(f"✅ Successfully ingested {total_docs} documents from {len(results)} sources!")
                        
                        # Show breakdown
                        for source, docs in results.items():
                            st.metric(f"{source.upper()}", len(docs))
                            
                    except Exception as e:
                        st.error(f"Error fetching feeds: {str(e)}")
        
        with col2:
            st.subheader("🎯 Individual Sources")
            
            source = st.selectbox(
                "Select Source",
                ["AlienVault OTX", "URLhaus", "ThreatFox"]
            )
            
            if st.button(f"Fetch from {source}", use_container_width=True):
                with st.spinner(f"Fetching from {source}..."):
                    try:
                        if source == "AlienVault OTX":
                            docs = aggregator.otx.get_pulses(limit=20)
                        elif source == "URLhaus":
                            docs = aggregator.urlhaus.get_recent_urls(limit=20)
                        elif source == "ThreatFox":
                            docs = aggregator.threatfox.get_recent_iocs(days=7)
                        
                        for doc_data in docs:
                            doc_id = storage.store_document(**doc_data)
                            extraction_result = extractor.extract_all(doc_data['content'])
                            storage.store_iocs(extraction_result['iocs'], doc_id)
                            storage.store_ttps(extraction_result['ttps'], doc_id)
                        
                        st.success(f"✅ Ingested {len(docs)} documents from {source}!")
                        
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        # Recent feeds
        st.markdown("---")
        st.subheader("📊 Recent Threat Intelligence")
        
        documents = storage.get_documents(limit=10)
        if documents:
            for doc in documents:
                with st.expander(f"📄 {doc['title'][:80]}..."):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.write(f"**Source:** {doc['source_type']}")
                    with col2:
                        st.write(f"**Date:** {doc['timestamp'][:10]}")
                    with col3:
                        st.write(f"**ID:** {doc['id']}")
                    
                    st.write(doc['content'][:500] + "...")
        
    except ImportError:
        st.error("Threat feeds module not available. Please check installation.")

def show_advanced_analytics_page(storage):
    """Display advanced analytics page with LLM-powered features."""
    
    st.header("🧠 Advanced AI-Powered Analytics")
    
    st.markdown("""
    <div class="info-card">
        <h3>🤖 LLM-Powered Threat Intelligence</h3>
        <p>Generate threat actor profiles, predict attacks, create playbooks, and more using advanced AI.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    try:
        from llm_analytics import AdvancedThreatAnalytics
        
        analytics = AdvancedThreatAnalytics()
        
        tab1, tab2, tab3, tab4 = st.tabs([
            "🎭 Threat Actor Profiling",
            "🔮 Attack Prediction",
            "📋 Report Generation",
            "🛡️ Playbook Generation"
        ])
        
        with tab1:
            st.subheader("🎭 AI Threat Actor Profiling")
            st.write("Generate detailed threat actor profiles based on campaign data.")
            
            campaigns = storage.get_campaigns()
            if campaigns:
                campaign_options = {f"{camp['name']} (ID: {camp['id']})": camp for camp in campaigns}
                selected_campaign = st.selectbox("Select Campaign", list(campaign_options.keys()))
                
                if st.button("🔍 Generate Profile", use_container_width=True):
                    with st.spinner("AI is analyzing the campaign..."):
                        campaign = campaign_options[selected_campaign]
                        
                        # Get campaign data
                        campaign_data = {
                            'name': campaign['name'],
                            'iocs': [],
                            'ttps': [],
                            'targeted_sectors': [],
                            'targeted_countries': []
                        }
                        
                        profile = analytics.generate_threat_actor_profile(campaign_data)
                        
                        st.markdown("### 📊 Threat Actor Profile")
                        st.markdown(profile)
            else:
                st.info("No campaigns available. Run fusion analysis first.")
        
        with tab2:
            st.subheader("🔮 Attack Pattern Prediction")
            st.write("Predict next attack vectors based on historical data.")
            
            if st.button("🎯 Predict Next Attack", use_container_width=True):
                with st.spinner("AI is analyzing patterns..."):
                    documents = storage.get_documents(limit=10)
                    historical_data = [
                        {
                            'title': doc['title'],
                            'date': doc['timestamp'],
                            'source': doc['source_type']
                        }
                        for doc in documents
                    ]
                    
                    prediction = analytics.predict_next_attack_vector(historical_data)
                    
                    st.markdown("### 🎯 Prediction Results")
                    st.markdown(prediction)
        
        with tab3:
            st.subheader("📋 Executive Report Generation")
            st.write("Generate executive-level threat intelligence reports.")
            
            if st.button("📝 Generate Report", use_container_width=True):
                with st.spinner("AI is generating report..."):
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
                    
                    report = analytics.generate_executive_report(threat_summary)
                    
                    st.markdown("### 📊 Executive Threat Report")
                    st.markdown(report)
                    
                    # Download button
                    st.download_button(
                        label="📥 Download Report",
                        data=report,
                        file_name="threat_intelligence_report.md",
                        mime="text/markdown"
                    )
        
        with tab4:
            st.subheader("🛡️ Incident Response Playbook")
            st.write("Generate automated incident response playbooks.")
            
            threat_type = st.selectbox(
                "Threat Type",
                ["Ransomware", "Phishing", "Malware", "APT", "DDoS"]
            )
            
            severity = st.selectbox(
                "Severity",
                ["Critical", "High", "Medium", "Low"]
            )
            
            if st.button("🚀 Generate Playbook", use_container_width=True):
                with st.spinner("AI is creating playbook..."):
                    threat_data = {
                        'threat_type': threat_type,
                        'severity': severity,
                        'iocs': [],
                        'ttps': [],
                        'affected_systems': []
                    }
                    
                    playbook = analytics.generate_response_playbook(threat_data)
                    
                    st.markdown("### 📋 Incident Response Playbook")
                    st.markdown(playbook)
                    
                    st.download_button(
                        label="📥 Download Playbook",
                        data=playbook,
                        file_name=f"{threat_type.lower()}_playbook.md",
                        mime="text/markdown"
                    )
    
    except ImportError as e:
        st.error(f"Advanced analytics module not available: {str(e)}")
    except Exception as e:
        st.error(f"Error: {str(e)}")

def show_performance_page():
    """Display system performance metrics."""
    from performance import monitor
    import pandas as pd
    import plotly.express as px
    
    st.header("⚡ System Performance Dashboard")
    
    # Refresh button
    if st.button("🔄 Refresh Metrics"):
        st.rerun()
        
    metrics = monitor.get_all_metrics()
    
    if not metrics:
        st.info("No performance metrics collected yet. Perform some operations (extraction, analysis) to generate data.")
        return

    # Summary Metrics Row
    st.subheader("📈 Latency Overview")
    col1, col2, col3 = st.columns(3)
    
    # 1. LLM Inference Latency
    llm_stats = monitor.get_statistics('llm_query_analyst')
    if llm_stats:
        with col1:
            st.metric(
                "Avg LLM Response Time", 
                f"{llm_stats['avg_latency']:.2f}s",
                help="Average time for Ollama to generate a response"
            )
            st.caption(f"Based on {llm_stats['count']} queries")
    else:
        with col1:
            st.metric("Avg LLM Response Time", "N/A")

    # 2. Extraction Latency
    extract_stats = monitor.get_statistics('extraction_total')
    if extract_stats:
        with col2:
            st.metric(
                "Avg Extraction Time", 
                f"{extract_stats['avg_latency']:.2f}s",
                help="Average time to process a full document"
            )
            st.caption(f"Based on {extract_stats['count']} documents")
    else:
        with col2:
            st.metric("Avg Extraction Time", "N/A")

    # 3. Request Throughput (Analyst)
    if llm_stats:
        with col3:
            st.metric(
                "Total AI Queries", 
                llm_stats['count'],
                help="Total number of AI analyst queries processed"
            )
    else:
        with col3:
            st.metric("Total AI Queries", "0")

    st.markdown("---")

    # Detailed Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🤖 LLM Latency Trend")
        if 'llm_query_analyst' in metrics:
            data = metrics['llm_query_analyst']
            df = pd.DataFrame(data)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig = px.line(df, x='timestamp', y='duration', 
                         title='LLM Response Time Over Time',
                         labels={'duration': 'Seconds', 'timestamp': 'Time'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No LLM query data available.")

    with col2:
        st.subheader("📄 Extraction Performance")
        if 'extraction_total' in metrics:
            data = metrics['extraction_total']
            df = pd.DataFrame(data)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig = px.bar(df, x='timestamp', y='duration',
                        title='Document Extraction Duration',
                        labels={'duration': 'Seconds', 'timestamp': 'Time'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No extraction data available.")

    # Detailed Statistics Table
    st.subheader("📊 Detailed Statistics")
    
    stats_data = []
    for op_type in metrics.keys():
        stats = monitor.get_statistics(op_type)
        if stats:
            stats_data.append({
                "Operation": op_type,
                "Count": stats['count'],
                "Avg (s)": f"{stats['avg_latency']:.2f}",
                "Min (s)": f"{stats['min_latency']:.2f}",
                "Max (s)": f"{stats['max_latency']:.2f}",
                "P95 (s)": f"{stats['p95_latency']:.2f}"
            })
            
    if stats_data:
        st.dataframe(pd.DataFrame(stats_data), use_container_width=True)

if __name__ == "__main__":
    main()
