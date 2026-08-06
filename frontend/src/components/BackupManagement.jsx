import React, { useState, useEffect } from 'react';

const BackupManagement = () => {
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [backupName, setBackupName] = useState('');

  useEffect(() => {
    fetchBackups();
  }, []);

  const fetchBackups = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/backup/list', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await response.json();
      setBackups(data);
    } catch (error) {
      console.error('Error fetching backups:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateBackup = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/backup/create', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ backup_name: backupName || null })
      });

      if (response.ok) {
        setBackupName('');
        fetchBackups();
      }
    } catch (error) {
      console.error('Error creating backup:', error);
    }
  };

  const handleRestoreBackup = async (backupName) => {
    if (!confirm(`Are you sure you want to restore backup: ${backupName}?`)) return;

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/backup/restore/${backupName}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        alert('Backup restored successfully!');
      }
    } catch (error) {
      console.error('Error restoring backup:', error);
    }
  };

  const handleDeleteBackup = async (backupName) => {
    if (!confirm(`Are you sure you want to delete backup: ${backupName}?`)) return;

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/backup/${backupName}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        fetchBackups();
      }
    } catch (error) {
      console.error('Error deleting backup:', error);
    }
  };

  const handleCleanup = async () => {
    if (!confirm('Are you sure you want to clean up old backups?')) return;

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/backup/cleanup', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        fetchBackups();
      }
    } catch (error) {
      console.error('Error cleaning up backups:', error);
    }
  };

  if (loading) return <div className="loading">Loading backups...</div>;

  return (
    <div className="backup-management">
      <div className="backup-header">
        <h2>💾 Backup Management</h2>
        <div className="backup-actions">
          <input
            placeholder="Backup name (optional)"
            value={backupName}
            onChange={(e) => setBackupName(e.target.value)}
          />
          <button className="btn-primary" onClick={handleCreateBackup}>
            Create Backup
          </button>
          <button className="btn-secondary" onClick={handleCleanup}>
            Cleanup Old
          </button>
        </div>
      </div>

      <div className="backups-table">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Created At</th>
              <th>Size</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {backups.map(backup => (
              <tr key={backup.name}>
                <td>{backup.name}</td>
                <td><span className="type-badge">{backup.type}</span></td>
                <td>{new Date(backup.created_at).toLocaleString()}</td>
                <td>{(backup.size / 1024 / 1024).toFixed(2)} MB</td>
                <td>
                  <button 
                    className="btn-success"
                    onClick={() => handleRestoreBackup(backup.name)}
                  >
                    Restore
                  </button>
                  <button 
                    className="btn-danger"
                    onClick={() => handleDeleteBackup(backup.name)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default BackupManagement;