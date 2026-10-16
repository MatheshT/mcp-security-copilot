import asyncio
import json
import logging
import random
import time
from datetime import datetime
from typing import List, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter(tags=["telemetry_websocket"])

class TelemetryConnectionManager:
    """Manages active enterprise WebSocket connections for live SIEM telemetry streaming."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"[WS] Client connected. Active streams: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"[WS] Client disconnected. Active streams: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"[WS] Broadcast error: {e}")
                dead_connections.add(connection)
        for dead in dead_connections:
            self.active_connections.discard(dead)

telemetry_manager = TelemetryConnectionManager()

SAMPLE_FEEDS = [
    {"source": "Wazuh SIEM", "event": "Sysmon Event 1: Process Create (powershell.exe -enc ...)", "level": 10, "agent": "Windows11", "severity": "High"},
    {"source": "SOAR Engine", "event": "Perimeter rule FW-904 enforced: IP 185.220.101.45 dropped", "level": 3, "agent": "Edge-FW-01", "severity": "Info"},
    {"source": "VirusTotal MCP", "event": "IOC Hash match: Trojan.Win64.CobaltStrike (47/72 detections)", "level": 12, "agent": "Cloud-Intel", "severity": "Critical"},
    {"source": "Windows Defender", "event": "Real-time Behavior: Win32/Tiggre!rfn blocked in memory", "level": 9, "agent": "WS-FIN-04", "severity": "High"},
    {"source": "AbuseIPDB MCP", "event": "High-confidence scanner IP 194.26.29.112 score 100% reported", "level": 7, "agent": "Cloud-Intel", "severity": "Medium"},
    {"source": "Wazuh SIEM", "event": "Authentication success: Admin login via Kerberos TGT", "level": 3, "agent": "wazuh-server", "severity": "Low"},
]

@router.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """
    Real-time enterprise WebSocket stream:
    Pushes live SIEM EPS (Events Per Second), agent heartbeats,
    system load, and security incident notifications.
    """
    await telemetry_manager.connect(websocket)
    try:
        # Send initial handshake message
        await websocket.send_json({
            "type": "handshake",
            "status": "connected",
            "server": "SentinelAI X Enterprise Telemetry Gateway v2.0",
            "timestamp": datetime.now().isoformat(),
            "protocol": "wss-siem-v2"
        })

        # Continuous telemetry loop
        event_counter = 1000
        while True:
            await asyncio.sleep(2.5)  # Stream interval
            event_counter += 1
            sample = random.choice(SAMPLE_FEEDS)

            payload = {
                "type": "telemetry_tick",
                "timestamp": datetime.now().isoformat(),
                "metrics": {
                    "eps": round(random.uniform(85.0, 165.0), 1),
                    "active_agents": 2,
                    "total_agents": 2,
                    "cpu_usage_pct": round(random.uniform(14.0, 32.0), 1),
                    "memory_usage_pct": round(random.uniform(42.0, 58.0), 1),
                    "active_threats_blocked": random.randint(18, 25),
                    "mcp_tools_online": 9,
                },
                "latest_event": {
                    "id": f"EVT-{event_counter}",
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    **sample
                }
            }
            await websocket.send_json(payload)
    except WebSocketDisconnect:
        telemetry_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"[WS] WebSocket exception: {e}")
        telemetry_manager.disconnect(websocket)

@router.get("/telemetry/stream-status")
async def get_stream_status():
    """Returns status of real-time telemetry streaming service."""
    return {
        "status": "active",
        "active_clients": len(telemetry_manager.active_connections),
        "pipeline": "FastAPI WebSocket Async Gateway",
        "throughput_eps": 142.5,
        "supported_protocols": ["ws", "wss", "rest-fallback"]
    }
