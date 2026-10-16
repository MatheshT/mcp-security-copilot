import React, { useState, useEffect } from 'react';
import api from '../../services/api';

const ComprehensiveInvestigationReport = ({ investigationData }) => {
  const [activeTab, setActiveTab] = useState('summary');
  const [expandedSections, setExpandedSections] = useState({});

  if (!investigationData) {
    return (
      <div style={{ padding: '20px', textAlign: 'center', color: '#64748b' }}>
        No investigation data available
      </div>
    );
  }

  const reportJson = investigationData.report_json || {};
  const extractedData = investigationData.extracted_data || {};
  const toolResponses = investigationData.tool_responses || [];

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const ToolReportCard = ({ toolName, data, icon }) => {
    if (!data) return null;

    return (
      <div style={{
        background: 'rgba(15,23,42,0.8)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '12px',
        padding: '20px',
        marginBottom: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
          <span style={{ fontSize: '24px' }}>{icon}</span>
          <h3 style={{ margin: 0, fontSize: '18px', color: '#e2e8f0' }}>{toolName}</h3>
        </div>
        <div style={{ color: '#94a3b8', fontSize: '14px' }}>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0 }}>
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      </div>
    );
  };

  const SeverityBadge = ({ severity }) => {
    const colors = {
      Critical: '#ef4444',
      High: '#f97316',
      Medium: '#eab308',
      Low: '#22c55e',
      Info: '#3b82f6'
    };
    return (
      <span style={{
        padding: '4px 12px',
        borderRadius: '4px',
        background: `${colors[severity] || '#64748b'}20`,
        color: colors[severity] || '#64748b',
        fontWeight: 600,
        fontSize: '12px'
      }}>
        {severity}
      </span>
    );
  };

  return (
    <div style={{
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      color: '#e2e8f0',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      padding: '24px',
      minHeight: '100vh'
    }}>
      {/* Header */}
      <div style={{
        marginBottom: '32px',
        paddingBottom: '20px',
        borderBottom: '1px solid rgba(255,255,255,0.1)'
      }}>
        <h1 style={{
          fontSize: '28px',
          fontWeight: 700,
          margin: '0 0 12px 0',
          background: 'linear-gradient(90deg, #3b82f6, #8b5cf6)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text'
        }}>
          🛡️ Comprehensive Security Investigation Report
        </h1>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
          <SeverityBadge severity={reportJson.severity} />
          <span style={{ color: '#94a3b8', fontSize: '14px' }}>
            Alert ID: {reportJson.alert_id}
          </span>
          <span style={{ color: '#94a3b8', fontSize: '14px' }}>
            Confidence: {reportJson.confidence}
          </span>
          <span style={{ color: '#94a3b8', fontSize: '14px' }}>
            Tools Used: {reportJson.tools_used?.length || 0}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '24px', flexWrap: 'wrap' }}>
        {['summary', 'wazuh', 'threat_intel', 'system_analysis', 'timeline', 'full_report'].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '10px 20px',
              background: activeTab === tab ? 'rgba(59, 130, 246, 0.2)' : 'rgba(255,255,255,0.05)',
              border: activeTab === tab ? '1px solid rgba(59, 130, 246, 0.4)' : '1px solid rgba(255,255,255,0.1)',
              borderRadius: '8px',
              color: activeTab === tab ? '#3b82f6' : '#94a3b8',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: 500,
              transition: 'all 0.2s'
            }}
          >
            {tab.replace('_', ' ').toUpperCase()}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === 'summary' && (
          <div style={{ display: 'grid', gap: '20px' }}>
            {/* Investigation Summary */}
            <div style={{
              background: 'rgba(15,23,42,0.8)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '12px',
              padding: '24px'
            }}>
              <h2 style={{ margin: '0 0 16px 0', fontSize: '20px', color: '#e2e8f0' }}>
                📋 Investigation Summary
              </h2>
              <p style={{ color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
                {reportJson.investigation_summary}
              </p>
            </div>

            {/* Key Findings */}
            <div style={{
              background: 'rgba(15,23,42,0.8)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '12px',
              padding: '24px'
            }}>
              <h2 style={{ margin: '0 0 16px 0', fontSize: '20px', color: '#e2e8f0' }}>
                🔍 Key Findings
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>ATTACK TYPE</div>
                  <div style={{ color: '#e2e8f0', fontSize: '16px', fontWeight: 600 }}>
                    {reportJson.attack_type}
                  </div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>AFFECTED HOST</div>
                  <div style={{ color: '#e2e8f0', fontSize: '16px', fontWeight: 600 }}>
                    {reportJson.affected_host}
                  </div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>SOURCE IP</div>
                  <div style={{ color: '#e2e8f0', fontSize: '16px', fontWeight: 600 }}>
                    {reportJson.source_ip}
                  </div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>DESTINATION IP</div>
                  <div style={{ color: '#e2e8f0', fontSize: '16px', fontWeight: 600 }}>
                    {reportJson.destination_ip}
                  </div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>MITRE TECHNIQUE</div>
                  <div style={{ color: '#e2e8f0', fontSize: '16px', fontWeight: 600 }}>
                    {reportJson.mitre_technique}
                  </div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>THREAT SCORE</div>
                  <div style={{ color: '#e2e8f0', fontSize: '16px', fontWeight: 600 }}>
                    {reportJson.visual_data?.threat_score || 0}/100
                  </div>
                </div>
              </div>
            </div>

            {/* Recommendations */}
            <div style={{
              background: 'rgba(15,23,42,0.8)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '12px',
              padding: '24px'
            }}>
              <h2 style={{ margin: '0 0 16px 0', fontSize: '20px', color: '#e2e8f0' }}>
                📝 Recommendations
              </h2>
              <ul style={{ margin: 0, paddingLeft: '20px', color: '#94a3b8' }}>
                {reportJson.recommendations?.map((rec, index) => (
                  <li key={index} style={{ marginBottom: '8px' }}>{rec}</li>
                ))}
              </ul>
            </div>

            {/* Data Collection Summary */}
            <div style={{
              background: 'rgba(15,23,42,0.8)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '12px',
              padding: '24px'
            }}>
              <h2 style={{ margin: '0 0 16px 0', fontSize: '20px', color: '#e2e8f0' }}>
                📊 Data Collection Summary
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '16px' }}>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>TOOLS USED</div>
                  <div style={{ color: '#3b82f6', fontSize: '24px', fontWeight: 700 }}>
                    {reportJson.data_collection_summary?.tools_used || 0}
                  </div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>DATA POINTS</div>
                  <div style={{ color: '#8b5cf6', fontSize: '24px', fontWeight: 700 }}>
                    {reportJson.data_collection_summary?.total_data_points || 0}
                  </div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', marginBottom: '4px' }}>SUCCESS RATE</div>
                  <div style={{ color: '#22c55e', fontSize: '24px', fontWeight: 700 }}>
                    {Math.round((reportJson.data_collection_summary?.tool_success_rate || 0) * 100)}%
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'wazuh' && (
          <div style={{ display: 'grid', gap: '20px' }}>
            <ToolReportCard
              toolName="Wazuh SIEM"
              data={reportJson.tool_reports?.wazuh_report}
              icon="🛡️"
            />
            {extractedData.wazuh_data && (
              <div style={{
                background: 'rgba(15,23,42,0.8)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '12px',
                padding: '20px'
              }}>
                <h3 style={{ margin: '0 0 16px 0', fontSize: '18px', color: '#e2e8f0' }}>
                  📊 Wazuh Raw Data
                </h3>
                <pre style={{ 
                  whiteSpace: 'pre-wrap', 
                  wordBreak: 'break-word', 
                  margin: 0,
                  color: '#94a3b8',
                  fontSize: '13px'
                }}>
                  {JSON.stringify(extractedData.wazuh_data, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}

        {activeTab === 'threat_intel' && (
          <div style={{ display: 'grid', gap: '20px' }}>
            <ToolReportCard
              toolName="VirusTotal"
              data={reportJson.tool_reports?.virustotal_report}
              icon="🦠"
            />
            <ToolReportCard
              toolName="MISP"
              data={reportJson.tool_reports?.misp_report}
              icon="🎯"
            />
            <ToolReportCard
              toolName="Shodan"
              data={reportJson.tool_reports?.shodan_report}
              icon="🌐"
            />
            <ToolReportCard
              toolName="AbuseIPDB"
              data={reportJson.tool_reports?.abuseipdb_report}
              icon="🚫"
            />
            <ToolReportCard
              toolName="AlienVault OTX"
              data={reportJson.tool_reports?.alienvault_report}
              icon="👁️"
            />
          </div>
        )}

        {activeTab === 'system_analysis' && (
          <div style={{ display: 'grid', gap: '20px' }}>
            <ToolReportCard
              toolName="Windows Defender"
              data={reportJson.tool_reports?.windows_defender_report}
              icon="🪟"
            />
            <ToolReportCard
              toolName="Windows Logs"
              data={reportJson.tool_reports?.windows_logs_report}
              icon="📝"
            />
            {extractedData.windows_defender_data && (
              <div style={{
                background: 'rgba(15,23,42,0.8)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '12px',
                padding: '20px'
              }}>
                <h3 style={{ margin: '0 0 16px 0', fontSize: '18px', color: '#e2e8f0' }}>
                  🪟 Windows Defender Raw Data
                </h3>
                <pre style={{ 
                  whiteSpace: 'pre-wrap', 
                  wordBreak: 'break-word', 
                  margin: 0,
                  color: '#94a3b8',
                  fontSize: '13px'
                }}>
                  {JSON.stringify(extractedData.windows_defender_data, null, 2)}
                </pre>
              </div>
            )}
            {extractedData.windows_logs_data && (
              <div style={{
                background: 'rgba(15,23,42,0.8)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '12px',
                padding: '20px'
              }}>
                <h3 style={{ margin: '0 0 16px 0', fontSize: '18px', color: '#e2e8f0' }}>
                  📝 Windows Logs Raw Data
                </h3>
                <pre style={{ 
                  whiteSpace: 'pre-wrap', 
                  wordBreak: 'break-word', 
                  margin: 0,
                  color: '#94a3b8',
                  fontSize: '13px'
                }}>
                  {JSON.stringify(extractedData.windows_logs_data, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}

        {activeTab === 'timeline' && (
          <div style={{
            background: 'rgba(15,23,42,0.8)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '12px',
            padding: '24px'
          }}>
            <h2 style={{ margin: '0 0 20px 0', fontSize: '20px', color: '#e2e8f0' }}>
              ⏱️ Attack Timeline
            </h2>
            {reportJson.visual_data?.timeline?.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {reportJson.visual_data.timeline.map((event, index) => (
                  <div key={index} style={{
                    display: 'flex',
                    gap: '16px',
                    padding: '12px',
                    background: 'rgba(255,255,255,0.02)',
                    borderRadius: '8px',
                    borderLeft: `3px solid ${event.severity >= 10 ? '#ef4444' : event.severity >= 7 ? '#f97316' : '#22c55e'}`
                  }}>
                    <div style={{ minWidth: '120px', color: '#64748b', fontSize: '13px' }}>
                      {new Date(event.timestamp).toLocaleString()}
                    </div>
                    <div style={{ flex: 1, color: '#e2e8f0', fontSize: '14px' }}>
                      {event.event}
                    </div>
                    <div style={{ minWidth: '40px', color: '#94a3b8', fontSize: '12px' }}>
                      Level {event.severity}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ color: '#64748b', textAlign: 'center', padding: '40px' }}>
                No timeline data available
              </div>
            )}
          </div>
        )}

        {activeTab === 'full_report' && (
          <div style={{
            background: 'rgba(15,23,42,0.8)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '12px',
            padding: '24px'
          }}>
            <h2 style={{ margin: '0 0 20px 0', fontSize: '20px', color: '#e2e8f0' }}>
              📄 Full Investigation Report
            </h2>
            <pre style={{ 
              whiteSpace: 'pre-wrap', 
              wordBreak: 'break-word', 
              margin: 0,
              color: '#94a3b8',
              fontSize: '13px'
            }}>
              {JSON.stringify(reportJson, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* Tool Usage Log */}
      <div style={{
        marginTop: '32px',
        background: 'rgba(15,23,42,0.8)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '12px',
        padding: '24px'
      }}>
        <h2 style={{ margin: '0 0 16px 0', fontSize: '20px', color: '#e2e8f0' }}>
          🔧 Tool Usage Log
        </h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {reportJson.visual_data?.tool_usage?.map((log, index) => (
            <div key={index} style={{
              display: 'flex',
              gap: '16px',
              padding: '12px',
              background: 'rgba(255,255,255,0.02)',
              borderRadius: '8px'
            }}>
              <span style={{ 
                minWidth: '20px', 
                color: '#64748b', 
                fontSize: '13px' 
              }}>
                {index + 1}.
              </span>
              <span style={{ 
                minWidth: '150px', 
                color: '#3b82f6', 
                fontWeight: 600,
                fontSize: '14px' 
              }}>
                {log.tool}
              </span>
              <span style={{ 
                color: log.status === 'completed' ? '#22c55e' : '#ef4444',
                fontSize: '13px' 
              }}>
                {log.status}
              </span>
              {log.data_points && (
                <span style={{ color: '#64748b', fontSize: '13px' }}>
                  ({log.data_points} data points)
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ComprehensiveInvestigationReport;