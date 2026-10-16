"""
Test script for enhanced AI capabilities
Tests log collection, IOC extraction, and autonomous investigation
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.log_collector.windows_log_collector import WindowsLogCollector
from app.log_collector.ioc_extractor import IOCExtractor, IOCPrioritizer
from app.soc_analyst.autonomous_analyst import AutonomousSOCAnalyst
from app.threat_intel.orchestrator import ThreatIntelOrchestrator
from app.utils.logger import get_logger

logger = get_logger(__name__)

async def test_log_collection():
    """Test enhanced log collection"""
    print("\n=== Testing Enhanced Log Collection ===")
    
    collector = WindowsLogCollector()
    
    # Test collecting from different sources
    sources = ["windows_event", "sysmon", "defender"]
    results = {}
    
    for source in sources:
        try:
            print(f"\nCollecting from {source}...")
            result = await collector.collect_specific_source(source, hours_back=1)
            results[source] = result
            print(f"✓ Collected {result.get('total_logs', 0)} logs from {source}")
        except Exception as e:
            print(f"✗ Error collecting from {source}: {e}")
            results[source] = {"error": str(e)}
    
    return results

async def test_ioc_extraction():
    """Test IOC extraction with enhanced patterns"""
    print("\n=== Testing Enhanced IOC Extraction ===")
    
    # Create some sample log data
    sample_logs = [
        {
            "log_source": "windows_event",
            "log_name": "Security",
            "event_id": 4625,
            "timestamp": "2024-01-15T10:30:00",
            "computer_name": "DESKTOP-ABC123",
            "source": "Security",
            "type": "Failure Audit",
            "user": "Administrator",
            "data": {
                "strings": ["192.168.1.100", "malicious-domain.com", "http://evil.com/payload.exe"]
            }
        },
        {
            "log_source": "sysmon",
            "log_name": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "timestamp": "2024-01-15T10:31:00",
            "computer_name": "DESKTOP-ABC123",
            "source": "Sysmon",
            "type": "Information",
            "user": "SYSTEM",
            "data": {
                "strings": [
                    "C:\\Windows\\System32\\powershell.exe",
                    "5d41402abc4b2a76b9719d911017c592",
                    "35.186.224.47"
                ]
            }
        }
    ]
    
    extractor = IOCExtractor()
    iocs = extractor.extract_iocs(sample_logs)
    
    print(f"\n✓ Processed {iocs['total_logs_processed']} logs")
    print(f"✓ Extracted {iocs['summary']['unique_ip_addresses']} unique IP addresses")
    print(f"✓ Extracted {iocs['summary']['unique_domains']} unique domains")
    print(f"✓ Extracted {iocs['summary']['total_file_hashes']} file hashes")
    print(f"✓ Extracted {iocs['summary']['unique_file_paths']} file paths")
    
    # Test prioritization
    prioritizer = IOCPrioritizer()
    prioritized = prioritizer.prioritize_iocs(iocs)
    
    print(f"\n✓ IOC Prioritization:")
    print(f"  - Critical: {len(prioritized['critical'])}")
    print(f"  - High: {len(prioritized['high'])}")
    print(f"  - Medium: {len(prioritized['medium'])}")
    print(f"  - Low: {len(prioritized['low'])}")
    
    return iocs

async def test_autonomous_investigation():
    """Test autonomous SOC investigation"""
    print("\n=== Testing Autonomous SOC Investigation ===")
    
    config = {
        "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
        "llm_provider": "free"  # Use free tier for testing
    }
    
    analyst = AutonomousSOCAnalyst(config)
    
    investigation_params = {
        "title": "Test Security Investigation",
        "description": "Testing autonomous investigation capabilities",
        "investigation_type": "malware",
        "log_sources": ["windows_event", "sysmon"],
        "time_range_hours": 1,
        "priority_areas": ["process_creation", "network_connections"],
        "ioc_focus": ["ip_addresses", "file_hashes"]
    }
    
    print(f"\nStarting investigation: {investigation_params['title']}")
    print(f"Type: {investigation_params['investigation_type']}")
    print(f"Log sources: {investigation_params['log_sources']}")
    
    try:
        result = await analyst.conduct_investigation(investigation_params)
        
        print(f"\n✓ Investigation completed: {result['status']}")
        print(f"✓ Investigation ID: {result['investigation_id']}")
        print(f"✓ Phases completed: {len(result['phases'])}")
        
        for i, phase in enumerate(result['phases'], 1):
            print(f"  Phase {i}: {phase.get('phase', 'unknown')}")
        
        if result['final_report']:
            print(f"\n✓ Final report generated")
            print(f"  Executive summary available: {bool(result['final_report'].get('executive_summary'))}")
        
        return result
        
    except Exception as e:
        print(f"✗ Investigation failed: {e}")
        return {"error": str(e)}

async def test_threat_intelligence():
    """Test threat intelligence integration"""
    print("\n=== Testing Threat Intelligence Integration ===")
    
    config = {
        "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY", "")
    }
    
    orchestrator = ThreatIntelOrchestrator(config)
    
    test_iocs = {
        "ip_addresses": ["8.8.8.8", "1.1.1.1"],
        "domains": ["google.com", "example.com"],
        "file_hashes": {
            "MD5": ["5d41402abc4b2a76b9719d911017c592"]
        }
    }
    
    print(f"\nTesting with {len(test_iocs['ip_addresses'])} IPs, {len(test_iocs['domains'])} domains")
    
    try:
        results = await orchestrator.analyze_iocs(test_iocs)
        await orchestrator.close()
        
        print(f"✓ Threat intelligence analysis completed")
        print(f"✓ Sources analyzed: {list(results.keys())}")
        
        return results
        
    except Exception as e:
        print(f"✗ Threat intelligence analysis failed: {e}")
        return {"error": str(e)}

async def run_all_tests():
    """Run all enhanced AI tests"""
    print("=" * 60)
    print("Enhanced AI Security Copilot - Test Suite")
    print("=" * 60)
    
    # Test 1: Log Collection
    log_results = await test_log_collection()
    
    # Test 2: IOC Extraction
    ioc_results = await test_ioc_extraction()
    
    # Test 3: Threat Intelligence
    threat_results = await test_threat_intelligence()
    
    # Test 4: Autonomous Investigation
    investigation_results = await test_autonomous_investigation()
    
    print("\n" + "=" * 60)
    print("Test Suite Completed")
    print("=" * 60)
    
    summary = {
        "log_collection": "success" if log_results else "failed",
        "ioc_extraction": "success" if ioc_results else "failed",
        "threat_intel": "success" if threat_results else "failed",
        "autonomous_investigation": "success" if investigation_results else "failed"
    }
    
    print("\nSummary:")
    for test_name, status in summary.items():
        symbol = "✓" if status == "success" else "✗"
        print(f"  {symbol} {test_name}: {status}")
    
    return summary

if __name__ == "__main__":
    try:
        results = asyncio.run(run_all_tests())
        print(f"\nOverall: {sum(1 for v in results.values() if v == 'success')}/{len(results)} tests passed")
    except Exception as e:
        print(f"\nTest suite failed with error: {e}")
        import traceback
        traceback.print_exc()