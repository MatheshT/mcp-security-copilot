import os
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
import gzip
import json
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class BackupManager:
    """Manage database and application backups"""
    
    def __init__(self):
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./security_copilot.db")
    
    def backup_database(self, backup_name: Optional[str] = None) -> str:
        """Create a database backup"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = backup_name or f"db_backup_{timestamp}"
        
        if self.database_url.startswith("sqlite"):
            return self._backup_sqlite(backup_name)
        elif "postgresql" in self.database_url:
            return self._backup_postgresql(backup_name)
        else:
            raise ValueError("Unsupported database type for backup")
    
    def _backup_sqlite(self, backup_name: str) -> str:
        """Backup SQLite database"""
        db_path = self.database_url.replace("sqlite:///", "")
        backup_path = self.backup_dir / f"{backup_name}.db"
        
        # Copy database file
        shutil.copy2(db_path, backup_path)
        
        # Compress the backup
        compressed_path = self.backup_dir / f"{backup_name}.db.gz"
        with open(backup_path, 'rb') as f_in:
            with gzip.open(compressed_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Remove uncompressed backup
        backup_path.unlink()
        
        # Create backup metadata
        self._create_backup_metadata(backup_name, "sqlite", str(compressed_path))
        
        return str(compressed_path)
    
    def _backup_postgresql(self, backup_name: str) -> str:
        """Backup PostgreSQL database"""
        backup_path = self.backup_dir / f"{backup_name}.sql"
        
        # Parse database URL
        # Format: postgresql://user:password@host:port/database
        parsed = self.database_url.replace("postgresql://", "")
        user_pass, host_db = parsed.split("@")
        user, password = user_pass.split(":")
        host_port, database = host_db.split("/")
        host = host_port.split(":")[0]
        
        # Set PGPASSWORD environment variable
        env = os.environ.copy()
        env["PGPASSWORD"] = password
        
        # Run pg_dump
        command = [
            "pg_dump",
            "-h", host,
            "-U", user,
            "-d", database,
            "-f", str(backup_path)
        ]
        
        try:
            subprocess.run(command, env=env, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"PostgreSQL backup failed: {e}")
        
        # Compress the backup
        compressed_path = self.backup_dir / f"{backup_name}.sql.gz"
        with open(backup_path, 'rb') as f_in:
            with gzip.open(compressed_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Remove uncompressed backup
        backup_path.unlink()
        
        # Create backup metadata
        self._create_backup_metadata(backup_name, "postgresql", str(compressed_path))
        
        return str(compressed_path)
    
    def _create_backup_metadata(self, backup_name: str, db_type: str, backup_path: str):
        """Create backup metadata file"""
        metadata = {
            "name": backup_name,
            "type": db_type,
            "path": backup_path,
            "created_at": datetime.now().isoformat(),
            "size": os.path.getsize(backup_path)
        }
        
        metadata_path = self.backup_dir / f"{backup_name}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def restore_database(self, backup_name: str) -> bool:
        """Restore database from backup"""
        metadata_path = self.backup_dir / f"{backup_name}.json"
        
        if not metadata_path.exists():
            raise FileNotFoundError(f"Backup metadata not found: {backup_name}")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        backup_path = metadata["path"]
        db_type = metadata["type"]
        
        if db_type == "sqlite":
            return self._restore_sqlite(backup_path)
        elif db_type == "postgresql":
            return self._restore_postgresql(backup_path)
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
    
    def _restore_sqlite(self, backup_path: str) -> bool:
        """Restore SQLite database"""
        db_path = self.database_url.replace("sqlite:///", "")
        
        # Decompress backup
        with gzip.open(backup_path, 'rb') as f_in:
            with open(db_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        return True
    
    def _restore_postgresql(self, backup_path: str) -> bool:
        """Restore PostgreSQL database"""
        # Decompress backup
        temp_sql = backup_path.replace(".gz", "")
        with gzip.open(backup_path, 'rb') as f_in:
            with open(temp_sql, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Parse database URL
        parsed = self.database_url.replace("postgresql://", "")
        user_pass, host_db = parsed.split("@")
        user, password = user_pass.split(":")
        host_port, database = host_db.split("/")
        host = host_port.split(":")[0]
        
        # Set PGPASSWORD environment variable
        env = os.environ.copy()
        env["PGPASSWORD"] = password
        
        # Run psql to restore
        command = [
            "psql",
            "-h", host,
            "-U", user,
            "-d", database,
            "-f", temp_sql
        ]
        
        try:
            subprocess.run(command, env=env, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"PostgreSQL restore failed: {e}")
        finally:
            # Remove temporary SQL file
            os.unlink(temp_sql)
        
        return True
    
    def list_backups(self) -> list:
        """List all available backups"""
        backups = []
        
        for metadata_file in self.backup_dir.glob("*.json"):
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            backups.append(metadata)
        
        return sorted(backups, key=lambda x: x["created_at"], reverse=True)
    
    def delete_backup(self, backup_name: str) -> bool:
        """Delete a backup"""
        metadata_path = self.backup_dir / f"{backup_name}.json"
        
        if not metadata_path.exists():
            return False
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Delete backup file
        backup_path = Path(metadata["path"])
        if backup_path.exists():
            backup_path.unlink()
        
        # Delete metadata
        metadata_path.unlink()
        
        return True
    
    def cleanup_old_backups(self, keep_count: int = 10) -> int:
        """Remove old backups, keeping only the most recent ones"""
        backups = self.list_backups()
        
        if len(backups) <= keep_count:
            return 0
        
        # Remove old backups
        old_backups = backups[keep_count:]
        deleted_count = 0
        
        for backup in old_backups:
            if self.delete_backup(backup["name"]):
                deleted_count += 1
        
        return deleted_count

# Global backup manager instance
backup_manager = BackupManager()