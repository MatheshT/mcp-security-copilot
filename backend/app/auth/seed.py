from sqlalchemy.orm import Session
from .models import User, Role, Permission

def seed_default_data(db: Session):
    """Seed default roles, permissions, and initial admin user"""
    
    # Check if data already exists
    if db.query(Role).count() > 0:
        print("Database already seeded with default data")
        return
    
    # Create default permissions
    permissions = [
        # Investigation permissions
        Permission(name="read_investigations", resource="investigations", action="read", 
                  description="View investigations and alerts"),
        Permission(name="write_investigations", resource="investigations", action="write",
                  description="Create and update investigations"),
        Permission(name="delete_investigations", resource="investigations", action="delete",
                  description="Delete investigations"),
        Permission(name="manage_investigations", resource="investigations", action="manage",
                  description="Full management of investigations"),
        
        # User management permissions
        Permission(name="read_users", resource="users", action="read",
                  description="View user information"),
        Permission(name="write_users", resource="users", action="write",
                  description="Create and update users"),
        Permission(name="delete_users", resource="users", action="delete",
                  description="Delete users"),
        Permission(name="manage_users", resource="users", action="manage",
                  description="Full user management"),
        
        # Report permissions
        Permission(name="read_reports", resource="reports", action="read",
                  description="View security reports"),
        Permission(name="write_reports", resource="reports", action="write",
                  description="Create and generate reports"),
        Permission(name="delete_reports", resource="reports", action="delete",
                  description="Delete reports"),
        
        # Dashboard permissions
        Permission(name="read_dashboard", resource="dashboard", action="read",
                  description="View dashboard statistics"),
        
        # Admin permissions
        Permission(name="system_admin", resource="system", action="admin",
                  description="Full system administration"),
        Permission(name="audit_logs", resource="audit", action="read",
                  description="View audit logs"),
    ]
    
    for perm in permissions:
        db.add(perm)
    
    # Create default roles
    admin_role = Role(
        name="admin",
        description="Full system administrator",
        is_system=True
    )
    
    analyst_role = Role(
        name="analyst",
        description="Security analyst with investigation access",
        is_system=True
    )
    
    viewer_role = Role(
        name="viewer",
        description="Read-only access to security data",
        is_system=True
    )
    
    db.add(admin_role)
    db.add(analyst_role)
    db.add(viewer_role)
    db.flush()  # Flush to get IDs
    
    # Assign permissions to roles
    # Admin role gets all permissions
    admin_role.permissions = permissions
    
    # Analyst role gets investigation and report permissions
    analyst_permissions = [p for p in permissions if p.resource in ["investigations", "reports", "dashboard"]]
    analyst_role.permissions = analyst_permissions
    
    # Viewer role gets read permissions only
    viewer_permissions = [p for p in permissions if p.action == "read"]
    viewer_role.permissions = viewer_permissions
    
    # Create default admin user
    from .service import AuthService
    auth_service = AuthService(db)
    
    admin_user = User(
        username="admin",
        email="admin@security-copilot.local",
        hashed_password=auth_service.get_password_hash("admin123"),  # Change in production!
        full_name="System Administrator",
        is_active=True,
        is_superuser=True
    )
    admin_user.roles = [admin_role]
    db.add(admin_user)
    
    db.commit()
    
    print("Database seeded with default roles, permissions, and admin user")
    print("Default admin credentials: username='admin', password='admin123'")
    print("IMPORTANT: Change the default admin password in production!")