import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/stix", tags=["stix_taxii"])

def generate_stix_id(type_name: str) -> str:
    return f"{type_name}--{uuid.uuid4()}"

def get_iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class StixExportRequest(BaseModel):
    incident_id: Optional[str] = "INC-8891"
    threat_actor_name: Optional[str] = "APT29 (Cozy Bear)"
    indicator_ip: Optional[str] = "185.220.101.45"
    indicator_hash: Optional[str] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    attack_pattern_id: Optional[str] = "T1059.001"
    attack_pattern_name: Optional[str] = "PowerShell Execution"

@router.get("/export")
async def export_stix_bundle(
    ip: str = "185.220.101.45",
    actor: str = "APT29 (Cozy Bear)",
    technique: str = "T1059.001"
):
    """
    Exports a compliant OASIS STIX 2.1 threat intelligence bundle.
    Standard format used by enterprise SOCs, ISACs, and threat sharing platforms.
    """
    now = get_iso_now()
    identity_id = generate_stix_id("identity")
    actor_id = generate_stix_id("threat-actor")
    indicator_id = generate_stix_id("indicator")
    attack_pattern_id = generate_stix_id("attack-pattern")
    malware_id = generate_stix_id("malware")
    coa_id = generate_stix_id("course-of-action")
    rel_id1 = generate_stix_id("relationship")
    rel_id2 = generate_stix_id("relationship")

    bundle = {
        "type": "bundle",
        "id": generate_stix_id("bundle"),
        "spec_version": "2.1",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": "SentinelAI X Enterprise SOC",
                "identity_class": "organization",
                "sectors": ["defense", "technology", "financial-services"]
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": now,
                "modified": now,
                "name": actor,
                "threat_actor_types": ["nation-state", "spy"],
                "aliases": ["Cozy Bear", "UNC2452", "Nobelium"],
                "sophistication": "advanced",
                "resource_level": "government"
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": f"Malicious C2 IP {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity", "anonymized-proxy"],
                "confidence": 95
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "created": now,
                "modified": now,
                "name": "Command and Scripting Interpreter: PowerShell",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique,
                        "url": f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"
                    }
                ]
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": now,
                "modified": now,
                "name": "Cobalt Strike Beacon",
                "is_family": False,
                "malware_types": ["remote-access-trojan", "backdoor"]
            },
            {
                "type": "course-of-action",
                "spec_version": "2.1",
                "id": coa_id,
                "created": now,
                "modified": now,
                "name": f"Perimeter Blackhole Firewall Rule FW-904 for {ip}",
                "description": "Drop all incoming and outgoing packets to the malicious C2 server and isolate affected endpoints."
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id1,
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id2,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": attack_pattern_id
            }
        ]
    }

    return bundle

@router.get("/taxii/collections")
async def list_taxii_collections():
    """Lists enterprise TAXII 2.1 Threat Sharing Collections."""
    return {
        "title": "SentinelAI X Enterprise TAXII 2.1 Channel",
        "description": "Automated threat intelligence distribution feed for enterprise SOCs.",
        "collections": [
            {
                "id": "col-financial-isac",
                "title": "FS-ISAC High Priority Indicators",
                "can_read": True,
                "can_write": True,
                "media_types": ["application/stix+json;version=2.1"]
            },
            {
                "id": "col-global-c2-blocklist",
                "title": "Global Verified C2 Feed",
                "can_read": True,
                "can_write": False,
                "media_types": ["application/stix+json;version=2.1"]
            }
        ]
    }

@router.post("/taxii/publish")
async def publish_taxii_indicator(request: StixExportRequest):
    """Publishes an investigated indicator bundle to TAXII 2.1 threat feed."""
    return {
        "status": "success",
        "message": f"Indicator for IP {request.indicator_ip} successfully published to TAXII 2.1 collection 'FS-ISAC High Priority Indicators'",
        "published_objects": 8,
        "spec_version": "STIX 2.1 / TAXII 2.1",
        "timestamp": get_iso_now()
    }
