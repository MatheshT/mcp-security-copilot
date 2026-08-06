# Quick Start Guide - MCP Security Copilot v2.0 Enterprise Edition

## ✅ Implementation Status

All enterprise features have been successfully implemented and are ready to use:

### 🔐 Authentication & Security
- ✅ JWT-based authentication with refresh tokens
- ✅ Role-Based Access Control (RBAC)
- ✅ User management system (CRUD operations)
- ✅ Session management
- ✅ Audit logging
- ✅ Input sanitization (SQL injection, XSS protection)
- ✅ Rate limiting
- ✅ Security headers (CSP, CORS, etc.)
- ✅ IP whitelisting/blacklisting

### 🗄️ Database & Performance
- ✅ SQLAlchemy ORM with PostgreSQL/SQLite support
- ✅ Connection pooling
- ✅ Redis caching layer
- ✅ Database backup and recovery system

### 📊 Monitoring & Operations
- ✅ Prometheus metrics
- ✅ Structured JSON logging
- ✅ Health check endpoints
- ✅ API documentation (OpenAPI/Swagger)

### 🚀 Deployment & DevOps
- ✅ Docker Compose configuration
- ✅ Kubernetes manifests
- ✅ GitHub Actions CI/CD pipeline
- ✅ Feature flag system
- ✅ API versioning (v1, v2)

### 🧪 Testing
- ✅ Backend testing (pytest)
- ✅ Frontend testing (Vitest)
- ✅ Coverage reporting

## 🚀 How to Run

### Option 1: Using the Start Script (Recommended for Windows)

1. Double-click `start.bat` in the project root
2. This will automatically start both backend and frontend servers
3. Open your browser to `http://localhost:5173`

### Option 2: Manual Startup

#### Backend Setup:
```bash
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -c "from app.database import init_db; init_db()"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend Setup:
```bash
cd frontend
npm install
npx vite --host 0.0.0.0 --port 5173
```

### Option 3: Docker Compose
```bash
docker-compose up --build
```

## 🔑 Default Credentials

- **Username**: `admin`
- **Password**: `admin123`
- **⚠️ IMPORTANT**: Change the default password in production!

## 📚 Key Endpoints

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/register` - Register new user
- `GET /api/auth/me` - Get current user info
- `GET /api/auth/permissions` - Get user permissions

### API Documentation
- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`
- OpenAPI JSON: `http://localhost:8000/api/openapi.json`

### Monitoring
- Health Check: `http://localhost:8000/health`
- Prometheus Metrics: `http://localhost:8000/metrics`
- System Info: `http://localhost:8000/api/info`

### User Management
- `GET /api/users/` - List all users
- `POST /api/users/` - Create new user
- `GET /api/users/{id}` - Get user details
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

### Audit & Monitoring
- `GET /api/audit/` - View audit logs
- `GET /api/backup/list` - List backups
- `POST /api/backup/create` - Create backup

### Feature Flags
- `GET /api/feature-flags/` - List all feature flags
- `PUT /api/feature-flags/{name}` - Update feature flag

## 🎯 Using the Application

1. **Login**: Use the default admin credentials to login
2. **Investigate**: Submit security investigation queries
3. **Monitor**: View dashboard statistics and security metrics
4. **Manage**: Use the admin panel to manage users and permissions
5. **Audit**: Review audit logs for security events

## 🔧 Configuration

Edit the `.env` file to configure:
- Database connection (PostgreSQL/SQLite)
- Security tool API keys (Wazuh, VirusTotal, MISP, Shodan)
- LLM provider (OpenAI, Ollama, or free)
- Monitoring settings
- Security parameters

## 📁 Project Structure Overview

```
MCP-Security-Copilot/
├── backend/
│   ├── app/
│   │   ├── auth/              # Authentication & authorization
│   │   ├── monitoring/        # Prometheus metrics
│   │   ├── middleware/        # Security & error handling
│   │   ├── routes/           # API endpoints (v1, v2)
│   │   └── utils/           # Utilities (cache, backup, etc.)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   └── services/        # API services
│   └── package.json
├── docker-compose.yml
├── k8s-deployment.yaml
├── start.bat               # Quick start script
└── README.md              # Full documentation
```

## 🐛 Troubleshooting

### Backend won't start
- Ensure Python 3.8+ is installed
- Check that all dependencies are installed: `pip install -r requirements.txt`
- Verify database initialization: `python -c "from app.database import init_db; init_db()"`

### Frontend won't start
- Ensure Node.js 20+ is installed
- Check that dependencies are installed: `npm install`
- Try running with npx: `npx vite`

### Database errors
- Check DATABASE_URL in .env file
- For SQLite, ensure the file path is correct
- For PostgreSQL, ensure the database is running

### Permission errors
- Run as administrator if needed
- Check file permissions on project directory

## 📞 Support

For issues or questions:
1. Check the API documentation at `/api/docs`
2. Review the README.md for detailed information
3. Check the logs in the backend console
4. Verify environment variables are set correctly

## 🎉 You're Ready!

The MCP Security Copilot Enterprise Edition is now running with all enterprise features enabled. Start exploring the comprehensive security investigation platform!