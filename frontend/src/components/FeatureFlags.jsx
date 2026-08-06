import React, { useState, useEffect } from 'react';

const FeatureFlags = () => {
  const [flags, setFlags] = useState({});
  const [loading, setLoading] = useState(true);
  const [editingFlag, setEditingFlag] = useState(null);

  useEffect(() => {
    fetchFlags();
  }, []);

  const fetchFlags = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/feature-flags/', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await response.json();
      setFlags(data);
    } catch (error) {
      console.error('Error fetching feature flags:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleFlag = async (flagName, currentEnabled) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/feature-flags/${flagName}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          enabled: !currentEnabled,
          rollout_percentage: flags[flagName].rollout_percentage
        })
      });

      if (response.ok) {
        fetchFlags();
      }
    } catch (error) {
      console.error('Error toggling flag:', error);
    }
  };

  const handleUpdateRollout = async (flagName, rolloutPercentage) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/feature-flags/${flagName}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          enabled: flags[flagName].enabled,
          rollout_percentage: parseInt(rolloutPercentage)
        })
      });

      if (response.ok) {
        fetchFlags();
        setEditingFlag(null);
      }
    } catch (error) {
      console.error('Error updating rollout:', error);
    }
  };

  if (loading) return <div className="loading">Loading feature flags...</div>;

  return (
    <div className="feature-flags">
      <div className="flags-header">
        <h2>🎯 Feature Flags</h2>
        <p className="subtitle">Manage feature availability and rollout percentages</p>
      </div>

      <div className="flags-grid">
        {Object.entries(flags).map(([name, config]) => (
          <div key={name} className="flag-card">
            <div className="flag-header">
              <h3>{name}</h3>
              <div className="flag-toggle">
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={config.enabled}
                    onChange={() => handleToggleFlag(name, config.enabled)}
                  />
                  <span className="slider"></span>
                </label>
              </div>
            </div>
            
            <p className="flag-description">{config.description}</p>
            
            <div className="flag-rollout">
              <label>Rollout: {config.rollout_percentage}%</label>
              {editingFlag === name ? (
                <div className="rollout-edit">
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={config.rollout_percentage}
                    onChange={(e) => handleUpdateRollout(name, e.target.value)}
                  />
                  <button onClick={() => setEditingFlag(null)}>Done</button>
                </div>
              ) : (
                <button onClick={() => setEditingFlag(name)}>Edit</button>
              )}
            </div>
            
            <div className="flag-status">
              <span className={`status-badge ${config.enabled ? 'enabled' : 'disabled'}`}>
                {config.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default FeatureFlags;