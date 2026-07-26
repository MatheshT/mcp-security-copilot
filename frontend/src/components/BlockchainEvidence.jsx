import React, { useState } from 'react';

const BlockchainEvidence = () => {
  const [evidenceBlocks, setEvidenceBlocks] = useState([]);
  const [selectedBlock, setSelectedBlock] = useState(null);
  const [loading, setLoading] = useState(false);
  const [newEvidence, setNewEvidence] = useState({ type: 'log', data: '' });

  const createEvidenceBlock = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/evidence/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          evidence_data: {
            type: newEvidence.type,
            data: newEvidence.data,
            timestamp: new Date().toISOString()
          },
          investigator_id: 'analyst-1',
          signature: 'digital-signature-placeholder'
        })
      });
      const data = await response.json();
      setEvidenceBlocks([...evidenceBlocks, data.block]);
      setNewEvidence({ type: 'log', data: '' });
    } catch (error) {
      console.error('Error creating evidence block:', error);
    } finally {
      setLoading(false);
    }
  };

  const verifyEvidence = async (blockId) => {
    try {
      const response = await fetch(`/api/evidence/${blockId}/verify`);
      const data = await response.json();
      setSelectedBlock(prev => ({ ...prev, verification: data.verification }));
    } catch (error) {
      console.error('Error verifying evidence:', error);
    }
  };

  const generateCertificate = async (blockId) => {
    try {
      const response = await fetch(`/api/evidence/${blockId}/certificate`);
      const data = await response.json();
      setSelectedBlock(prev => ({ ...prev, certificate: data.certificate }));
    } catch (error) {
      console.error('Error generating certificate:', error);
    }
  };

  return (
    <div className="blockchain-evidence">
      <div className="header">
        <h2>🔗 Blockchain Evidence Integrity</h2>
      </div>

      <div className="evidence-creation">
        <h3>Create Evidence Block</h3>
        <div className="evidence-form">
          <select
            value={newEvidence.type}
            onChange={(e) => setNewEvidence({ ...newEvidence, type: e.target.value })}
            className="form-select"
          >
            <option value="log">Security Log</option>
            <option value="screenshot">Screenshot</option>
            <option value="network_capture">Network Capture</option>
            <option value="memory_dump">Memory Dump</option>
            <option value="file_hash">File Hash</option>
          </select>
          <textarea
            value={newEvidence.data}
            onChange={(e) => setNewEvidence({ ...newEvidence, data: e.target.value })}
            placeholder="Enter evidence data..."
            className="evidence-input"
          />
          <button 
            className="btn-primary"
            onClick={createEvidenceBlock}
            disabled={loading || !newEvidence.data.trim()}
          >
            {loading ? 'Creating Block...' : 'Create Evidence Block'}
          </button>
        </div>
      </div>

      <div className="evidence-chain">
        <h3>Evidence Chain</h3>
        {evidenceBlocks.length === 0 ? (
          <p className="no-evidence">No evidence blocks created yet</p>
        ) : (
          <div className="chain-visualization">
            {evidenceBlocks.map((block, index) => (
              <div 
                key={index}
                className={`chain-block ${selectedBlock?.block_id === block.block_id ? 'selected' : ''}`}
                onClick={() => setSelectedBlock(block)}
              >
                <div className="block-header">
                  <span className="block-height">Block #{block.block_height}</span>
                  <span className="block-id">{block.block_id?.slice(0, 8)}</span>
                </div>
                <div className="block-hash">{block.block_hash?.slice(0, 16)}...</div>
                <div className="block-timestamp">{block.timestamp}</div>
                <div className={`block-status ${block.verification_status}`}>
                  {block.verification_status}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {selectedBlock && (
        <div className="block-details">
          <h3>Block Details</h3>
          <div className="details-grid">
            <div className="detail-item">
              <span className="label">Block ID:</span>
              <span className="value">{selectedBlock.block_id}</span>
            </div>
            <div className="detail-item">
              <span className="label">Block Height:</span>
              <span className="value">{selectedBlock.block_height}</span>
            </div>
            <div className="detail-item">
              <span className="label">Timestamp:</span>
              <span className="value">{selectedBlock.timestamp}</span>
            </div>
            <div className="detail-item">
              <span className="label">Block Hash:</span>
              <span className="value hash">{selectedBlock.block_hash}</span>
            </div>
            <div className="detail-item">
              <span className="label">Chain Integrity:</span>
              <span className={`value ${selectedBlock.chain_integrity ? 'valid' : 'invalid'}`}>
                {selectedBlock.chain_integrity ? 'Valid' : 'Invalid'}
              </span>
            </div>
          </div>

          <div className="block-actions">
            <button 
              className="btn-secondary"
              onClick={() => verifyEvidence(selectedBlock.block_id)}
            >
              Verify Integrity
            </button>
            <button 
              className="btn-secondary"
              onClick={() => generateCertificate(selectedBlock.block_id)}
            >
              Generate Certificate
            </button>
          </div>

          {selectedBlock.verification && (
            <div className="verification-result">
              <h4>Verification Result</h4>
              <div className={`verification-status ${selectedBlock.verification.valid ? 'valid' : 'invalid'}`}>
                {selectedBlock.verification.valid ? '✓ Valid' : '✗ Invalid'}
              </div>
              {selectedBlock.verification.error && (
                <div className="verification-error">
                  {selectedBlock.verification.error}
                </div>
              )}
            </div>
          )}

          {selectedBlock.certificate && (
            <div className="certificate-display">
              <h4>Evidence Certificate</h4>
              <div className="certificate-details">
                <div className="detail-item">
                  <span className="label">Certificate ID:</span>
                  <span className="value">{selectedBlock.certificate.certificate_id}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Type:</span>
                  <span className="value">{selectedBlock.certificate.certificate_type}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Legal Admissibility:</span>
                  <span className="value">{selectedBlock.certificate.legal_admissibility}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default BlockchainEvidence;