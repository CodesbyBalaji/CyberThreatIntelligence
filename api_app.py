"""
FastAPI application exposing high-performance JSON APIs and TAXII server endpoints.
"""

from fastapi import FastAPI, HTTPException, Request, Header, Response
from fastapi.responses import JSONResponse
from storage import ThreatStorage
import uvicorn
import json

app = FastAPI(title="CyberShield Threat Intelligence API", version="2.1.0")
storage = ThreatStorage()

# ─── TAXII 2.1 SERVER ENDPOINTS ──────────────────────────────────────────

@app.get("/taxii2/")
async def taxii_discovery():
    """TAXII Discovery Endpoint"""
    return {
        "title": "CyberShield TAXII 2.1 Server",
        "description": "Enterprise Threat Intelligence Feed Integration",
        "contact": "cti@cybershield.local",
        "default": "https://api.cybershield.local/taxii2/api1/",
        "api_roots": [
            "https://api.cybershield.local/taxii2/api1/"
        ]
    }

@app.get("/taxii2/api1/")
async def taxii_api_root():
    """TAXII API Root Endpoint"""
    return {
        "title": "CyberShield Core API Root",
        "versions": ["taxii-2.1"],
        "max_content_length": 10485760
    }

@app.get("/taxii2/api1/collections/")
async def taxii_collections():
    """List TAXII Collections"""
    return {
        "collections": [
            {
                "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
                "title": "High Confidence IOCs",
                "description": "Indicators of Compromise with confidence > 80%",
                "can_read": True,
                "can_write": False,
                "media_types": [
                    "application/taxi+json;version=2.1"
                ]
            }
        ]
    }

@app.get("/taxii2/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/")
async def taxii_collection_objects(request: Request):
    """Get objects from the collection (STIX 2.1 format)"""
    from export_integration import ExtractorExportManager
    
    iocs = storage.get_iocs(limit=100)
    high_conf_iocs = [ioc for ioc in iocs if ioc.get('confidence', 0) > 0.8]
    
    manager = ExtractorExportManager(storage)
    bundle_str = manager.export_stix2_iocs(high_conf_iocs)
    bundle_json = json.loads(bundle_str)
    
    return JSONResponse(
        content={"objects": bundle_json.get('objects', [])},
        media_type="application/taxii+json;version=2.1"
    )

# ─── JSON API ENDPOINTS (Custom FastAPI Interfaces) ──────────────────────

@app.get("/api/v1/health")
async def health_check():
    """System health check endpoint"""
    return {"status": "healthy", "components": {"database": "online", "llm": "ready"}}

@app.get("/api/v1/iocs")
async def get_iocs(limit: int = 50, threat_type: str = None):
    """Retrieve tracked Indicators of Compromise (JSON format)"""
    iocs = storage.get_iocs(limit=limit)
    if threat_type:
        iocs = [i for i in iocs if i.get('type') == threat_type]
    
    # ensure it's JSON serializable
    return {"success": True, "count": len(iocs), "data": iocs}

@app.get("/api/v1/campaigns")
async def get_campaigns(limit: int = 20):
    """Retrieve active malware campaigns and threat actors"""
    campaigns = storage.get_campaigns(limit=limit)
    return {"success": True, "count": len(campaigns), "data": campaigns}

if __name__ == "__main__":
    print("Starting CyberShield FastAPI Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
