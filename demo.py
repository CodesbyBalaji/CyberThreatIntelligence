#!/usr/bin/env python3
"""
Demo script for the LLM-powered Threat Fusion Engine.
Demonstrates the complete pipeline from ingestion to analysis.
"""

import os
import sys
import time
import json
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

from storage import ThreatStorage
from ingest import ThreatIngestor
from extract import ThreatExtractor
from fusion import ThreatFusion
from analyst import ThreatAnalyst

def print_banner():
    """Print demo banner."""
    print("=" * 60)
    print("🛡️  LLM-POWERED THREAT FUSION ENGINE DEMO")
    print("=" * 60)
    print()

def print_step(step_num, title):
    """Print step header."""
    print(f"\n📋 STEP {step_num}: {title}")
    print("-" * 50)

def wait_for_user():
    """Wait for user input to continue."""
    input("\n⏸️  Press Enter to continue...")

def main():
    """Run the complete demo."""

    print_banner()

    print("This demo will walk you through the complete threat fusion pipeline:")
    print("1. Initialize system components")
    print("2. Ingest sample threat intelligence data")
    print("3. Extract IOCs and TTPs using AI")
    print("4. Correlate documents and detect campaigns")
    print("5. Query the AI analyst")
    print("6. Visualize results")

    wait_for_user()

    # Step 1: Initialize Components
    print_step(1, "INITIALIZING SYSTEM COMPONENTS")

    try:
        storage = ThreatStorage()
        ingestor = ThreatIngestor()
        extractor = ThreatExtractor()
        fusion = ThreatFusion()
        analyst = ThreatAnalyst(storage)

        print("✅ Storage system initialized")
        print("✅ Data ingestion module ready")
        print("✅ IOC/TTP extraction engine ready")
        print("✅ Fusion and correlation engine ready")
        print("✅ AI analyst ready")

    except Exception as e:
        print(f"❌ Error initializing components: {str(e)}")
        print("💡 Make sure Ollama is running: ollama serve")
        return

    wait_for_user()

    # Step 2: Ingest Sample Data
    print_step(2, "INGESTING THREAT INTELLIGENCE DATA")

    documents = []
    total_docs = 0

    # Ingest blog samples
    print("📖 Ingesting security blog posts...")
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
                documents.append(storage.get_document_by_id(doc_id))
                total_docs += 1
                print(f"  ✅ Processed: {blog['title'][:50]}...")

    except Exception as e:
        print(f"  ❌ Error ingesting blogs: {str(e)}")

    # Ingest OSINT feeds
    print("\n🔍 Ingesting OSINT feeds...")
    try:
        osint_documents = ingestor.ingest_osint_feed('alientvault_otx')
        for doc_data in osint_documents:
            doc_id = storage.store_document(**doc_data)
            documents.append(storage.get_document_by_id(doc_id))
            total_docs += 1
            print(f"  ✅ Processed: {doc_data['title'][:50]}...")

    except Exception as e:
        print(f"  ❌ Error ingesting OSINT: {str(e)}")

    # Ingest dark web posts
    print("\n🕵️ Ingesting dark web intelligence...")
    try:
        darkweb_documents = ingestor.ingest_darkweb_posts('data/darkweb')
        for doc_data in darkweb_documents:
            doc_id = storage.store_document(**doc_data)
            documents.append(storage.get_document_by_id(doc_id))
            total_docs += 1
            print(f"  ✅ Processed: {doc_data['title'][:50]}...")

    except Exception as e:
        print(f"  ❌ Error ingesting dark web data: {str(e)}")

    print(f"\n📊 Total documents ingested: {total_docs}")

    wait_for_user()

    # Step 3: Extract IOCs and TTPs
    print_step(3, "EXTRACTING IOCs AND TTPs WITH AI")

    all_iocs = []
    all_ttps = []

    for i, doc in enumerate(documents, 1):
        print(f"\n🔍 Analyzing document {i}/{len(documents)}: {doc['title'][:40]}...")

        try:
            extraction_result = extractor.extract_all(doc['content'])

            # Store extractions
            storage.store_iocs(extraction_result['iocs'], doc['id'])
            storage.store_ttps(extraction_result['ttps'], doc['id'])

            all_iocs.extend(extraction_result['iocs'])
            all_ttps.extend(extraction_result['ttps'])

            print(f"  📍 Extracted {len(extraction_result['iocs'])} IOCs")
            print(f"  ⚔️ Extracted {len(extraction_result['ttps'])} TTPs")

            # Show sample extractions
            if extraction_result['iocs']:
                sample_ioc = extraction_result['iocs'][0]
                print(f"  💡 Sample IOC: {sample_ioc['value']} ({sample_ioc['type']})")

            if extraction_result['ttps']:
                sample_ttp = extraction_result['ttps'][0]
                print(f"  💡 Sample TTP: {sample_ttp['mitre_id']} - {sample_ttp['name']}")

        except Exception as e:
            print(f"  ❌ Error extracting from document {i}: {str(e)}")

    print(f"\n📊 EXTRACTION SUMMARY:")
    print(f"  🎯 Total IOCs: {len(all_iocs)}")
    print(f"  ⚔️ Total TTPs: {len(all_ttps)}")

    # IOC type breakdown
    ioc_types = {}
    for ioc in all_iocs:
        ioc_type = ioc['type']
        ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1

    print("\n📈 IOC Type Breakdown:")
    for ioc_type, count in ioc_types.items():
        print(f"  • {ioc_type}: {count}")

    wait_for_user()

    # Step 4: Fusion and Correlation
    print_step(4, "CORRELATING DOCUMENTS AND DETECTING CAMPAIGNS")

    try:
        print("🔗 Running fusion analysis...")

        # Get document IOCs and TTPs
        document_iocs = {}
        document_ttps = {}

        for doc in documents:
            doc_id = doc['id']
            document_iocs[doc_id] = storage.get_iocs_by_document(doc_id)
            document_ttps[doc_id] = storage.get_ttps_by_document(doc_id)

        # Run fusion pipeline
        fusion_results = fusion.fusion_pipeline(documents, document_iocs, document_ttps)

        print("✅ Fusion analysis completed!")

        # Display results
        correlations = fusion_results['correlations']
        campaigns = fusion_results['campaigns']

        print(f"\n📊 CORRELATION RESULTS:")
        print(f"  🎯 IOC-based correlations: {len(correlations['ioc_based'])}")
        print(f"  ⚔️ TTP-based correlations: {len(correlations['ttp_based'])}")
        print(f"  🧠 Semantic correlations: {len(correlations['semantic'])}")
        print(f"  📈 Total correlations: {correlations['total_count']}")

        print(f"\n🎭 CAMPAIGN DETECTION:")
        print(f"  🎯 Campaigns detected: {len(campaigns)}")

        for campaign in campaigns:
            print(f"  • {campaign['name']} (confidence: {campaign['confidence']:.2f}, docs: {campaign['document_count']})")

            # Store campaign in database
            storage.store_campaign(
                name=campaign['name'],
                document_ids=campaign['document_ids'],
                ioc_ids=[],
                ttp_ids=[],
                confidence=campaign['confidence'],
                metadata=campaign.get('metadata', {})
            )

        # Knowledge graph stats
        kg_stats = fusion_results['knowledge_graph_stats']
        print(f"\n🕸️ KNOWLEDGE GRAPH:")
        print(f"  📊 Nodes: {kg_stats['nodes']}")
        print(f"  🔗 Edges: {kg_stats['edges']}")

    except Exception as e:
        print(f"❌ Error in fusion analysis: {str(e)}")

    wait_for_user()

    # Step 5: AI Analyst Queries
    print_step(5, "QUERYING THE AI ANALYST")

    sample_queries = [
        "What are the most common attack techniques we've observed?",
        "Tell me about any APT activity in our data",
        "What ransomware indicators should we be watching for?"
    ]

    for i, query in enumerate(sample_queries, 1):
        print(f"\n🤖 Query {i}: {query}")
        print("🔍 Analyzing...")

        try:
            result = analyst.answer_query(query)

            if result['found_evidence']:
                print("\n💡 AI Analysis:")
                print(result['llm_response'][:500] + "..." if len(result['llm_response']) > 500 else result['llm_response'])
                print(f"\n📚 Based on {result['evidence_count']} evidence sources")
            else:
                print("❌ No relevant evidence found for this query")

        except Exception as e:
            print(f"❌ Error processing query: {str(e)}")

        if i < len(sample_queries):
            time.sleep(2)  # Brief pause between queries

    # IOC Analysis Demo
    print("\n🎯 IOC ANALYSIS DEMO")

    # Find a sample IOC to analyze
    sample_ioc = None
    if all_iocs:
        # Look for a domain IOC
        for ioc in all_iocs:
            if ioc['type'] == 'domain':
                sample_ioc = ioc['value']
                break

        if not sample_ioc and all_iocs:
            sample_ioc = all_iocs[0]['value']

    if sample_ioc:
        print(f"\n🔍 Analyzing IOC: {sample_ioc}")

        try:
            result = analyst.analyze_ioc(sample_ioc)

            if result['found']:
                print("\n💡 IOC Analysis:")
                print(result['llm_analysis'][:400] + "..." if len(result['llm_analysis']) > 400 else result['llm_analysis'])

                suggestions = analyst.suggest_investigations(result)
                print("\n🔬 Investigation Suggestions:")
                for suggestion in suggestions[:3]:
                    print(f"  • {suggestion}")
            else:
                print("❌ IOC not found in database")

        except Exception as e:
            print(f"❌ Error analyzing IOC: {str(e)}")

    wait_for_user()

    # Step 6: Summary and Next Steps
    print_step(6, "DEMO SUMMARY AND NEXT STEPS")

    print("🎉 Demo completed successfully!")
    print("\n📊 FINAL STATISTICS:")
    print(f"  📄 Documents processed: {len(documents)}")
    print(f"  🎯 IOCs extracted: {len(all_iocs)}")
    print(f"  ⚔️ TTPs identified: {len(all_ttps)}")
    print(f"  🎭 Campaigns detected: {len(campaigns) if 'campaigns' in locals() else 0}")
    print(f"  🔗 Correlations found: {correlations['total_count'] if 'correlations' in locals() else 0}")

    print("\n🚀 NEXT STEPS:")
    print("  1. Launch the Streamlit dashboard: streamlit run app.py")
    print("  2. Explore the interactive interface")
    print("  3. Upload your own threat intelligence documents")
    print("  4. Query the AI analyst with custom questions")
    print("  5. Investigate detected campaigns and IOCs")

    print("\n🔧 CONFIGURATION:")
    print("  • Database: threat_fusion.db")
    print("  • Knowledge graph: knowledge_graph.json")
    print("  • Vector index: threat_vectors.index")

    print("\n📚 DOCUMENTATION:")
    print("  • See README.md for detailed usage instructions")
    print("  • Check prompts/templates.json for AI prompt customization")
    print("  • Review data/ directory for sample data formats")

    print("\n" + "=" * 60)
    print("Demo completed! Thank you for trying the Threat Fusion Engine.")
    print("=" * 60)

if __name__ == "__main__":
    main()
