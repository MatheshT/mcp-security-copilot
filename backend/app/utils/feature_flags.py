import json
from typing import Dict, Any, Optional
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

class FeatureFlagManager:
    """Manage feature flags for the application"""
    
    def __init__(self):
        self.flags_file = Path("feature_flags.json")
        self.flags = self._load_flags()
    
    def _load_flags(self) -> Dict[str, Any]:
        """Load feature flags from file or use defaults"""
        default_flags = {
            "predictive_analytics": {
                "enabled": True,
                "description": "Enable predictive security analytics",
                "rollout_percentage": 100
            },
            "collaborative_investigation": {
                "enabled": True,
                "description": "Enable collaborative investigation features",
                "rollout_percentage": 100
            },
            "blockchain_evidence": {
                "enabled": True,
                "description": "Enable blockchain evidence integrity",
                "rollout_percentage": 100
            },
            "neural_anomaly_detection": {
                "enabled": True,
                "description": "Enable neural network anomaly detection",
                "rollout_percentage": 100
            },
            "threat_actor_persona": {
                "enabled": True,
                "description": "Enable threat actor persona analysis",
                "rollout_percentage": 100
            },
            "automated_response": {
                "enabled": True,
                "description": "Enable automated response orchestration",
                "rollout_percentage": 100
            },
            "real_time_monitoring": {
                "enabled": False,
                "description": "Enable real-time security monitoring",
                "rollout_percentage": 0
            },
            "advanced_reporting": {
                "enabled": True,
                "description": "Enable advanced reporting features",
                "rollout_percentage": 100
            },
            "api_v2": {
                "enabled": True,
                "description": "Enable API v2 endpoints",
                "rollout_percentage": 100
            },
            "dark_mode": {
                "enabled": True,
                "description": "Enable dark mode UI",
                "rollout_percentage": 100
            }
        }
        
        # Try to load from file
        if self.flags_file.exists():
            try:
                with open(self.flags_file, 'r') as f:
                    file_flags = json.load(f)
                    # Merge with defaults
                    for key, value in file_flags.items():
                        if key in default_flags:
                            default_flags[key].update(value)
                        else:
                            default_flags[key] = value
            except (json.JSONDecodeError, IOError):
                pass
        
        return default_flags
    
    def _save_flags(self):
        """Save feature flags to file"""
        with open(self.flags_file, 'w') as f:
            json.dump(self.flags, f, indent=2)
    
    def is_enabled(self, flag_name: str, user_id: Optional[int] = None) -> bool:
        """Check if a feature flag is enabled"""
        if flag_name not in self.flags:
            return False
        
        flag = self.flags[flag_name]
        
        if not flag.get("enabled", False):
            return False
        
        # Check rollout percentage if user_id is provided
        if user_id is not None and "rollout_percentage" in flag:
            rollout = flag["rollout_percentage"]
            if rollout < 100:
                # Simple hash-based rollout
                hash_value = hash(user_id) % 100
                return hash_value < rollout
        
        return True
    
    def get_flag(self, flag_name: str) -> Optional[Dict[str, Any]]:
        """Get feature flag configuration"""
        return self.flags.get(flag_name)
    
    def set_flag(self, flag_name: str, enabled: bool, rollout_percentage: int = 100):
        """Set feature flag configuration"""
        if flag_name not in self.flags:
            self.flags[flag_name] = {
                "enabled": enabled,
                "description": "",
                "rollout_percentage": rollout_percentage
            }
        else:
            self.flags[flag_name]["enabled"] = enabled
            self.flags[flag_name]["rollout_percentage"] = rollout_percentage
        
        self._save_flags()
    
    def list_flags(self) -> Dict[str, Any]:
        """List all feature flags"""
        return self.flags
    
    def update_flag_description(self, flag_name: str, description: str):
        """Update feature flag description"""
        if flag_name in self.flags:
            self.flags[flag_name]["description"] = description
            self._save_flags()

# Global feature flag manager instance
feature_flag_manager = FeatureFlagManager()

def feature_enabled(flag_name: str, user_id: Optional[int] = None) -> bool:
    """Decorator to check if a feature is enabled"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not feature_flag_manager.is_enabled(flag_name, user_id):
                raise ValueError(f"Feature '{flag_name}' is not enabled")
            return func(*args, **kwargs)
        return wrapper
    return decorator