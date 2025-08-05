import os
import json
import subprocess
import logging
import re
import shlex
import psutil
import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, status, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, ValidationError, Field, field_validator
from datetime import datetime, timedelta, timezone
from pathlib import Path
import contextlib
import asyncio
import aiofiles
from collections import defaultdict
import uuid
import jwt
import hashlib
import aiohttp
import asyncio
from typing import Optional
import structlog
from structlog.stdlib import LoggerFactory
import logging.handlers
import uuid
import asyncio
from functools import lru_cache
import redis
from cachetools import TTLCache
import threading
from concurrent.futures import ThreadPoolExecutor

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# --- Authentication Models and Functions ---

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    username: str
    email: Optional[str] = None
    role: str = "user"  # admin or user
    is_active: bool = True

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    token: str
    user: User

def load_users() -> Dict[str, Dict]:
    """Load users from JSON database"""
    if not USERS_DB.exists():
        # Create default admin user
        default_users = {
            "admin": {
                "username": "admin",
                "password": "admin123",  # Change this in production
                "email": "admin@ptsi.co.id",
                "role": "admin",
                "is_active": True
            }
        }
        USERS_DB.parent.mkdir(parents=True, exist_ok=True)
        with open(USERS_DB, 'w') as f:
            json.dump(default_users, f, indent=2)
        return default_users
    
    try:
        with open(USERS_DB, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading users: {e}")
        return {}

def save_users(users: Dict[str, Dict]):
    """Save users to JSON database"""
    try:
        with open(USERS_DB, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving users: {e}")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using simple hash comparison"""
    return hashed_password == plain_password  # In production, use proper hashing

def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate user with username and password"""
    users = load_users()
    user_data = users.get(username)
    
    if not user_data:
        return None
    
    if not user_data.get("is_active", True):
        return None
    
    if not verify_password(password, user_data.get("password", "")):
        return None
    
    return User(
        username=user_data["username"],
        email=user_data.get("email"),
        role=user_data.get("role", "user"),
        is_active=user_data.get("is_active", True)
    )

def create_access_token(data: dict):
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = verify_token(token)
    if payload is None:
        raise credentials_exception
    
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
    
    users = load_users()
    user_data = users.get(username)
    if user_data is None:
        raise credentials_exception
    
    return User(
        username=user_data["username"],
        email=user_data.get("email"),
        role=user_data.get("role", "user"),
        is_active=user_data.get("is_active", True)
    )

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role for endpoint"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

# --- Configuration ---
BASE_DIR = Path("/opt/vps-manager")
NGINX_DIR = Path("/etc/nginx")
NGINX_SITES_AVAILABLE = NGINX_DIR / "sites-available"
NGINX_SITES_ENABLED = NGINX_DIR / "sites-enabled"
CONFIG_DB = BASE_DIR / "app" / "config_db.json"
USERS_DB = BASE_DIR / "app" / "users_db.json"
LOG_DIR = BASE_DIR / "logs"
BACKUP_DIR = BASE_DIR / "backups"
TEMPLATES_DIR = BASE_DIR / "templates"

# SSL Configuration
DEFAULT_SSL_CERT = Path("/etc/ssl/ptsi/wildcard.ptsi.co.id.crt")
DEFAULT_SSL_KEY = Path("/etc/ssl/ptsi/wildcard.ptsi.co.id.key")
LETSENCRYPT_DIR = Path("/etc/letsencrypt/live")

# Rate Limiting
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 3600  # 1 hour

# --- Setup Logging ---
LOG_FILE_APP = LOG_DIR / "vps-manager.log"
LOG_FILE_NGINX_ACCESS_PREFIX = LOG_DIR
LOG_FILE_NGINX_ERROR_PREFIX = LOG_DIR

# Ensure directories exist
STATIC_DIR = Path("static")
for directory in [LOG_DIR, BACKUP_DIR, TEMPLATES_DIR, NGINX_SITES_AVAILABLE, NGINX_SITES_ENABLED, STATIC_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_APP, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Initialize FastAPI App ---
app = FastAPI(
    title="VPS Manager API - Surveyor Indonesia",
    description="Advanced reverse proxy management system by Surveyor Indonesia",
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None
)

# Add CORS middleware with more specific configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://10.3.1.111:3000", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.options("/{full_path:path}")
async def options_handler(full_path: str):
    """Handle preflight OPTIONS requests"""
    return {"message": "OK"}

# Serve static files (create directory if it doesn't exist)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# --- Rate Limiting ---
request_counts = defaultdict(list)

def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    # Clean old requests
    request_counts[client_ip] = [req_time for req_time in request_counts[client_ip] 
                                if now - req_time < RATE_LIMIT_WINDOW]
    
    if len(request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
        return False
    
    request_counts[client_ip].append(now)
    return True

# --- Enhanced Models ---
class ProxyLocation(BaseModel):
    path: str = Field(..., pattern=r"^/[a-zA-Z0-9_\-/]*$")
    backend: str
    proxy_http_version: Optional[str] = Field(None, pattern=r"^1\.(0|1)$")
    websocket: bool = False
    ssl_verify: bool = True
    custom_headers: Optional[Dict[str, str]] = {}
    rate_limit: Optional[str] = None  # e.g., "10r/s"
    auth_basic: Optional[str] = None
    client_max_body_size: Optional[str] = "1m"

    @field_validator("backend")
    def validate_backend(cls, v):
        if v.startswith(('http://', 'https://')):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(v)
                if not parsed.hostname:
                    raise ValueError("Invalid URL format")
                if parsed.port:
                    if not (1 <= parsed.port <= 65535):
                        raise ValueError("Port must be between 1 and 65535")
                return v
            except Exception:
                raise ValueError("Invalid URL format")
        else:
            if ':' in v:
                parts = v.rsplit(':', 1)
                if len(parts) != 2:
                    raise ValueError("Backend must be in format 'host:port' or 'scheme://host:port'")
                
                host, port = parts
                try:
                    port_int = int(port)
                    if not (1 <= port_int <= 65535):
                        raise ValueError("Port must be between 1 and 65535")
                except ValueError:
                    raise ValueError("Port must be a valid integer")
            else:
                if not v or not v.replace('-', '').replace('.', '').replace('_', '').isalnum():
                    raise ValueError("Invalid hostname format")
            
            return v

class LoadBalancerUpstream(BaseModel):
    name: str
    servers: List[str]
    method: str = "round_robin"  # round_robin, least_conn, ip_hash
    health_check: bool = True

class ServerConfig(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9_\-]+$")
    server_name: Optional[str] = None
    listen_port: int = Field(80, ge=1, le=65535)
    locations: List[ProxyLocation] = Field(..., min_length=1)
    upstream: Optional[LoadBalancerUpstream] = None
    is_active: bool = True
    rate_limit_global: Optional[str] = None
    access_log_enabled: bool = True
    error_log_enabled: bool = True
    gzip_enabled: bool = True
    security_headers: bool = True
    port_forward_only: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: Optional[str] = None

    @field_validator("server_name")
    def validate_server_name_for_port_forward(cls, v, info):
        if info.data.get("port_forward_only", False) and v:
            raise ValueError("server_name must be empty when port_forward_only is True")
        return v

class ConfigTemplate(BaseModel):
    name: str
    description: str
    config: Dict[str, Any]
    category: str = "general"

class BackupInfo(BaseModel):
    filename: str
    created_at: str
    size: int
    config_count: int

class SystemStats(BaseModel):
    nginx_status: str
    nginx_version: str
    api_pid: int
    uptime: str
    load_average: float
    cpu_usage: float
    memory_usage: float
    memory_used: float
    memory_total: float
    disk_usage: float
    disk_used: float
    disk_total: float
    ssl_certs: int
    ssl_expiring: int

# --- New Models for Additional Features ---
class SSLCertificate(BaseModel):
    domain: str
    issuer: str
    expires: str
    status: str  # valid, expiring, expired
    auto_renew: bool = True
    cert_path: Optional[str] = None
    key_path: Optional[str] = None

class LoadBalancerPool(BaseModel):
    name: str
    method: str = "round_robin"  # round_robin, least_conn, ip_hash
    servers: List[Dict[str, Any]]  # address, weight, status, max_fails, fail_timeout
    health_check: bool = True
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class LogEntry(BaseModel):
    timestamp: str
    level: str
    message: str
    source: str  # nginx, api, system
    user_id: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    duration_ms: Optional[float] = None
    status_code: Optional[int] = None
    request_id: Optional[str] = None

class LogFilter(BaseModel):
    level: Optional[str] = None
    source: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    user_id: Optional[str] = None
    action: Optional[str] = None
    limit: int = 1000

class LogRetentionPolicy(BaseModel):
    nginx_logs_days: int = 30
    api_logs_days: int = 90
    system_logs_days: int = 365
    audit_logs_days: int = 2555  # 7 years for compliance
    enabled: bool = True

class BackupRequest(BaseModel):
    include_configs: bool = True
    include_logs: bool = False
    include_ssl: bool = True
    description: Optional[str] = None

class RestoreRequest(BaseModel):
    filename: str
    overwrite_existing: bool = False

# --- Real-time Monitoring Models ---
class SystemMetrics(BaseModel):
    timestamp: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_in: float
    network_out: float
    nginx_connections: int
    nginx_requests_per_second: float

class ConfigMetrics(BaseModel):
    config_id: str
    timestamp: str
    requests_total: int
    requests_per_second: float
    response_time_avg: float
    error_rate: float
    bandwidth_used: float
    active_connections: int

class AlertRule(BaseModel):
    id: str
    name: str
    metric: str  # cpu, memory, disk, response_time, error_rate
    threshold: float
    operator: str  # >, <, >=, <=, ==
    duration: int  # seconds
    enabled: bool = True
    notification_email: Optional[str] = None
    notification_webhook: Optional[str] = None

class Alert(BaseModel):
    id: str
    rule_id: str
    timestamp: str
    metric: str
    value: float
    threshold: float
    status: str  # active, resolved
    message: str

# --- Frontend Form Models ---
class ProxyLocationForm(BaseModel):
    path: str = Field(..., pattern=r"^/[a-zA-Z0-9_\-/]*$")
    backend: str
    websocket: bool = False
    ssl_verify: bool = True
    custom_headers: Optional[Dict[str, str]] = {}
    rate_limit: Optional[str] = None
    auth_basic: Optional[str] = None
    client_max_body_size: Optional[str] = "1m"

class ServerConfigForm(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9_\-]+$")
    server_name: Optional[str] = None
    listen_port: int = Field(80, ge=1, le=65535)
    locations: List[ProxyLocationForm] = Field(..., min_length=1)
    upstream: Optional[LoadBalancerUpstream] = None
    is_active: bool = True
    rate_limit_global: Optional[str] = None
    access_log_enabled: bool = True
    error_log_enabled: bool = True
    gzip_enabled: bool = True
    security_headers: bool = True
    port_forward_only: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_cert_content: Optional[str] = None  # For inline certificate content
    ssl_key_content: Optional[str] = None   # For inline key content

class SSLUploadRequest(BaseModel):
    domain: str
    cert_content: str
    key_content: str

# --- Authentication Endpoints ---
@app.post("/api/auth/login", response_model=TokenResponse)
async def login(login_data: LoginRequest):
    """Authenticate user and return JWT token"""
    user = authenticate_user(login_data.username, login_data.password)
    logger.info(f"User {user.username} logged in successfully")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token = create_access_token(data={"sub": user.username})
    
    user_response = User(**user.model_dump())
    
    logger.info(f"User {user.username} logged in successfully")
    
    return TokenResponse(token=access_token, user=user_response)

@app.get("/api/auth/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user

@app.post("/api/auth/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user (client should remove token)"""
    logger.info(f"User {current_user.username} logged out")
    return {"message": "Successfully logged out"}

# --- Utility Functions ---
def run_command(cmd: List[str]) -> str:
    """Executes a shell command and returns its stdout."""
    safe_cmd = ' '.join(shlex.quote(arg) for arg in cmd)
    logger.info(f"Executing command: {safe_cmd}")
    try:
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            timeout=30
        )
        logger.info(f"Command successful: {result.stdout.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed: '{safe_cmd}' - Exit code: {e.returncode} - Stderr: {e.stderr.strip()}"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out: '{safe_cmd}'"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)
    except Exception as e:
        error_msg = f"Unexpected error running command '{safe_cmd}': {str(e)}"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)

async def load_configs() -> List[ServerConfig]:
    """Loads server configurations from the JSON database file."""
    if not CONFIG_DB.exists():
        logger.info(f"Config database not found at {CONFIG_DB}. Returning empty list.")
        return []
    
    try:
        async with aiofiles.open(CONFIG_DB, 'r', encoding='utf-8') as f:
            content = await f.read()
            data = json.loads(content)
        
        configs = []
        for item in data:
            try:
                # Migrate old configs to include new fields
                if 'ssl_cert' not in item:
                    item['ssl_cert'] = None
                if 'ssl_key' not in item:
                    item['ssl_key'] = None
                if 'port_forward_only' not in item:
                    item['port_forward_only'] = False
                
                # Set default SSL certificate paths for domain-based configs
                if not item.get('port_forward_only', False) and item.get('server_name'):
                    item['ssl_cert'] = str(DEFAULT_SSL_CERT)
                    item['ssl_key'] = str(DEFAULT_SSL_KEY)
                
                configs.append(ServerConfig(**item))
            except ValidationError as e:
                logger.warning(f"Skipping invalid config entry: {json.dumps(item)} - Errors: {e.errors()}")
        return configs
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {CONFIG_DB}: {str(e)}")
        raise HTTPException(status_code=500, detail="Configuration database is corrupted")
    except Exception as e:
        logger.error(f"Unexpected error loading configurations: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to load configurations")

async def save_configs(configs: List[ServerConfig]):
    """Saves server configurations to the JSON database file."""
    try:
        CONFIG_DB.parent.mkdir(parents=True, exist_ok=True)
        async with aiofiles.open(CONFIG_DB, 'w', encoding='utf-8') as f:
            content = json.dumps(
                [config.model_dump(mode='json') for config in configs],
                indent=2,
                ensure_ascii=False,
                default=str
            )
            await f.write(content)
        logger.info(f"Configurations saved to {CONFIG_DB}")
    except Exception as e:
        logger.error(f"Failed to save configurations: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to save configurations")

def generate_upstream_block(upstream: LoadBalancerUpstream) -> str:
    """Generates Nginx upstream block for load balancing."""
    block = f"upstream {upstream.name} {{\n"
    
    if upstream.method == "least_conn":
        block += "    least_conn;\n"
    elif upstream.method == "ip_hash":
        block += "    ip_hash;\n"
    
    for server in upstream.servers:
        block += f"    server {server}"
        if upstream.health_check:
            block += " max_fails=3 fail_timeout=30s"
        block += ";\n"
    
    block += "}\n\n"
    return block

def generate_location_block(location: ProxyLocation, upstream_name: Optional[str] = None) -> str:
    """Generates an Nginx location block configuration string."""
    sanitized_path = location.path.replace('"', '\\"').replace(';', '')
    
    block = f"\n    location {sanitized_path} {{\n"
    
    if location.rate_limit:
        block += f"        limit_req zone=api burst=10 nodelay;\n"
    
    if location.auth_basic:
        block += f'        auth_basic "{location.auth_basic}";\n'
        block += f'        auth_basic_user_file /etc/nginx/.htpasswd;\n'
    
    if location.client_max_body_size:
        block += f"        client_max_body_size {location.client_max_body_size};\n"
    
    if upstream_name:
        proxy_pass_target = f"http://{upstream_name}"
    elif location.backend.startswith(('http://', 'https://')):
        proxy_pass_target = location.backend
    else:
        proxy_pass_target = f"http://{location.backend}"

    block += f"        proxy_pass {proxy_pass_target};\n"
    
    headers = [
        "Host $host",
        "X-Real-IP $remote_addr",
        "X-Forwarded-For $proxy_add_x_forwarded_for",
        "X-Forwarded-Proto $scheme"
    ]
    
    if location.websocket:
        headers.extend([
            "Upgrade $http_upgrade",
            'Connection "upgrade"'
        ])
        block += "        proxy_http_version 1.1;\n"
    
    if location.proxy_http_version:
        block += f"        proxy_http_version {location.proxy_http_version};\n"
    
    if proxy_pass_target.startswith('https://') and not location.ssl_verify:
        block += "        proxy_ssl_verify off;\n"
    
    block += "        proxy_connect_timeout 60s;\n"
    block += "        proxy_send_timeout 60s;\n"
    block += "        proxy_read_timeout 60s;\n"
    
    for header in headers:
        block += f"        proxy_set_header {header};\n"
    
    for header, value in location.custom_headers.items():
        sanitized_value = value.replace('"', '\\"').replace('\n', '')
        block += f'        proxy_set_header {header} "{sanitized_value}";\n'
    
    block += "    }\n"
    return block

def generate_nginx_config_content(config: ServerConfig) -> str:
    """Generates the full Nginx server block configuration."""
    
    # Handle server_name for port forwarding vs domain-based configs
    server_name_directive = ""
    if config.server_name:
        server_name = re.sub(r'[;\{\}]', '', config.server_name)
        server_name_directive = f"server_name {server_name};"
    
    upstream_block = ""
    upstream_name = None
    if config.upstream:
        upstream_name = config.upstream.name
        upstream_block = generate_upstream_block(config.upstream)
    
    # Determine listen directive based on port forwarding mode
    if config.port_forward_only:
        listen_directive = f"listen {config.listen_port};"
        ssl_directives = ""
    else:
        listen_directive = f"listen {config.listen_port} ssl http2"
        
        # Use custom SSL certificate if provided, otherwise use default
        ssl_cert = config.ssl_cert if config.ssl_cert else str(DEFAULT_SSL_CERT)
        ssl_key = config.ssl_key if config.ssl_key else str(DEFAULT_SSL_KEY)
        
        ssl_directives = f"""
        ssl_certificate {ssl_cert};
        ssl_certificate_key {ssl_key};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;
        ssl_stapling on;
        ssl_stapling_verify off;
        """

    rate_limit_directives = ""
    if config.rate_limit_global:
        rate_limit_directives = f"""
        limit_req_zone $binary_remote_addr zone=global:{config.rate_limit_global};
        limit_req zone=global burst=20 nodelay;
        """

    location_blocks = "".join(generate_location_block(loc, upstream_name) for loc in config.locations)

    security_headers = ""
    if config.security_headers and not config.port_forward_only:
        security_headers = """
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        """

    gzip_config = ""
    if config.gzip_enabled:
        gzip_config = """
        gzip on;
        gzip_vary on;
        gzip_min_length 1024;
        gzip_proxied any;
        gzip_comp_level 6;
        gzip_types
            text/plain
            text/css
            text/xml
            text/javascript
            application/json
            application/javascript
            application/xml+rss
            application/atom+xml
            image/svg+xml;
        """

    access_log = f"access_log {LOG_FILE_NGINX_ACCESS_PREFIX / f'{config.id}_access.log'} main;" if config.access_log_enabled else "access_log off;"
    error_log = f"error_log {LOG_FILE_NGINX_ERROR_PREFIX / f'{config.id}_error.log'} warn;" if config.error_log_enabled else ""

    return f"""{upstream_block}server {{
    {listen_directive};
    {server_name_directive}

    {ssl_directives}
    {rate_limit_directives}

    {access_log}
    {error_log}

    {security_headers}
    {gzip_config}

    location ~ /\\. {{
        deny all;
    }}

    {location_blocks}
}}
"""

async def apply_nginx_config(config: ServerConfig):
    """Writes config to file, manages symlinks, and reloads Nginx."""
    config_file = NGINX_SITES_AVAILABLE / f"{config.id}.conf"
    enabled_link = NGINX_SITES_ENABLED / config_file.name

    try:
        config_content = generate_nginx_config_content(config)
        async with aiofiles.open(config_file, 'w', encoding='utf-8') as f:
            await f.write(config_content)
        logger.info(f"Config written: {config_file}")
    except Exception as e:
        logger.error(f"Config generation failed for {config.id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate config: {str(e)}")

    if config.is_active:
        if enabled_link.exists():
            enabled_link.unlink()
        enabled_link.symlink_to(config_file)
        logger.info(f"Enabled config: {enabled_link}")
    elif enabled_link.exists():
        enabled_link.unlink()
        logger.info(f"Disabled config: {enabled_link}")

    try:
        run_command(["nginx", "-t"])
        run_command(["systemctl", "reload", "nginx"])
        logger.info("Nginx reloaded successfully")
    except Exception as e:
        logger.error("Nginx reload failed! Configuration may be in inconsistent state")
        raise

def get_system_stats() -> SystemStats:
    """Get comprehensive system statistics."""
    try:
        try:
            nginx_status = run_command(["systemctl", "is-active", "nginx"]).strip()
        except:
            nginx_status = "inactive"
        
        try:
            nginx_version = run_command(["nginx", "-v"]).split('/')[-1]
        except:
            nginx_version = "unknown"
        
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_days = int(uptime_seconds // 86400)
        uptime_hours = int((uptime_seconds % 86400) // 3600)
        uptime_str = f"{uptime_days}d {uptime_hours}h"
        
        load_avg = os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0.0
        
        ssl_certs = 0
        ssl_expiring = 0
        try:
            if LETSENCRYPT_DIR.exists():
                ssl_certs = len(list(LETSENCRYPT_DIR.iterdir()))
                for cert_dir in LETSENCRYPT_DIR.iterdir():
                    cert_file = cert_dir / "cert.pem"
                    if cert_file.exists():
                        try:
                            result = run_command(["openssl", "x509", "-in", str(cert_file), "-noout", "-dates"])
                            ssl_expiring += 1 if "notAfter" in result else 0
                        except:
                            pass
        except:
            pass
        
        return SystemStats(
            nginx_status=nginx_status,
            nginx_version=nginx_version,
            api_pid=os.getpid(),
            uptime=uptime_str,
            load_average=load_avg,
            cpu_usage=cpu_percent,
            memory_usage=memory.percent,
            memory_used=round(memory.used / (1024**3), 2),
            memory_total=round(memory.total / (1024**3), 2),
            disk_usage=disk.percent,
            disk_used=round(disk.used / (1024**3), 2),
            disk_total=round(disk.total / (1024**3), 2),
            ssl_certs=ssl_certs,
            ssl_expiring=ssl_expiring
        )
    except Exception as e:
        logger.error(f"Failed to get system stats: {str(e)}")
        return SystemStats(
            nginx_status="unknown",
            nginx_version="unknown",
            api_pid=os.getpid(),
            uptime="0d 0h",
            load_average=0.0,
            cpu_usage=0.0,
            memory_usage=0.0,
            memory_used=0.0,
            memory_total=0.0,
            disk_usage=0.0,
            disk_used=0.0,
            disk_total=0.0,
            ssl_certs=0,
            ssl_expiring=0
        )

# --- Protected API Endpoints ---

@app.get("/api/configs", response_model=List[ServerConfig])
async def read_all_configs(current_user: User = Depends(get_current_user)):
    """Retrieves all configurations."""
    return await load_configs()

@app.get("/api/configs/{config_id}", response_model=ServerConfig)
async def read_single_config(config_id: str, current_user: User = Depends(get_current_user)):
    """Retrieves a specific configuration."""
    configs = await load_configs()
    for config in configs:
        if config.id == config_id:
            return config
    raise HTTPException(status_code=404, detail=f"Config with ID '{config_id}' not found")

@app.get("/api/configs/{config_id}/form")
async def get_config_for_form(config_id: str, current_user: User = Depends(get_current_user)):
    """Get configuration in form format for frontend editing."""
    configs = await load_configs()
    for config in configs:
        if config.id == config_id:
            # Convert to form format
            form_data = {
                "id": config.id,
                "server_name": config.server_name,
                "listen_port": config.listen_port,
                "locations": [
                    {
                        "path": loc.path,
                        "backend": loc.backend,
                        "websocket": loc.websocket,
                        "ssl_verify": loc.ssl_verify,
                        "custom_headers": loc.custom_headers or {},
                        "rate_limit": loc.rate_limit,
                        "auth_basic": loc.auth_basic,
                        "client_max_body_size": loc.client_max_body_size
                    }
                    for loc in config.locations
                ],
                "upstream": config.upstream.model_dump() if config.upstream else None,
                "is_active": config.is_active,
                "rate_limit_global": config.rate_limit_global,
                "access_log_enabled": config.access_log_enabled,
                "error_log_enabled": config.error_log_enabled,
                "gzip_enabled": config.gzip_enabled,
                "security_headers": config.security_headers,
                "port_forward_only": config.port_forward_only,
                "ssl_cert": config.ssl_cert,
                "ssl_key": config.ssl_key,
                "created_at": config.created_at,
                "updated_at": config.updated_at,
                "created_by": config.created_by
            }
            
            # Add SSL certificate content if available
            if config.ssl_cert and config.ssl_key:
                try:
                    async with aiofiles.open(config.ssl_cert, 'r') as f:
                        form_data["ssl_cert_content"] = await f.read()
                    async with aiofiles.open(config.ssl_key, 'r') as f:
                        form_data["ssl_key_content"] = await f.read()
                except Exception as e:
                    logger.warning(f"Could not read SSL certificate content: {e}")
            
            return form_data
    raise HTTPException(status_code=404, detail=f"Config with ID '{config_id}' not found")

@app.post("/api/configs", response_model=ServerConfig, status_code=201)
async def create_config(config: ServerConfigForm, current_user: User = Depends(get_current_user)):
    """Creates a new Nginx server configuration."""
    configs = await load_configs()
    
    if any(c.id == config.id for c in configs):
        raise HTTPException(status_code=409, detail=f"Config with ID '{config.id}' already exists")

    # Handle SSL certificate content if provided
    ssl_cert_path = None
    ssl_key_path = None
    
    if config.ssl_cert_content and config.ssl_key_content:
        # Create SSL certificate files
        ssl_dir = Path("/etc/ssl/custom")
        ssl_dir.mkdir(parents=True, exist_ok=True)
        
        ssl_cert_path = ssl_dir / f"{config.id}.crt"
        ssl_key_path = ssl_dir / f"{config.id}.key"
        
        try:
            # Write certificate content to files
            async with aiofiles.open(ssl_cert_path, 'w') as f:
                await f.write(config.ssl_cert_content)
            async with aiofiles.open(ssl_key_path, 'w') as f:
                await f.write(config.ssl_key_content)
            
            # Set proper permissions
            run_command(["chmod", "644", str(ssl_cert_path)])
            run_command(["chmod", "600", str(ssl_key_path)])
            
        except Exception as e:
            logger.error(f"Failed to write SSL certificate files: {e}")
            raise HTTPException(status_code=500, detail="Failed to create SSL certificate files")
    
    # Convert form data to ServerConfig
    server_config = ServerConfig(
        id=config.id,
        server_name=config.server_name,
        listen_port=config.listen_port,
        locations=[ProxyLocation(**loc.model_dump()) for loc in config.locations],
        upstream=config.upstream,
        is_active=config.is_active,
        rate_limit_global=config.rate_limit_global,
        access_log_enabled=config.access_log_enabled,
        error_log_enabled=config.error_log_enabled,
        gzip_enabled=config.gzip_enabled,
        security_headers=config.security_headers,
        port_forward_only=config.port_forward_only,
        ssl_cert=str(ssl_cert_path) if ssl_cert_path else config.ssl_cert,
        ssl_key=str(ssl_key_path) if ssl_key_path else config.ssl_key,
        created_by=current_user.username
    )
    
    # Set default SSL certificate paths for domain-based configs if no custom SSL provided
    if not config.port_forward_only and config.server_name and not ssl_cert_path:
        server_config.ssl_cert = str(DEFAULT_SSL_CERT)
        server_config.ssl_key = str(DEFAULT_SSL_KEY)
    
    configs.append(server_config)
    await save_configs(configs)
    await apply_nginx_config(server_config)
    
    # Send Telegram notification
    details = f"Created by {current_user.username}, Port: {config.listen_port}, SSL: {'Yes' if config.ssl_cert_content else 'No'}"
    asyncio.create_task(telegram_notifier.send_config_notification("create", config.id, details))
    
    logger.info(f"Config created by {current_user.username}: {config.id}")
    return server_config

class PortForwardRequest(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9_\-]+$")
    listen_port: int = Field(..., ge=1, le=65535)
    backend: str
    path: str = "/"

@app.post("/api/configs/port-forward", response_model=ServerConfig, status_code=201)
async def create_port_forward_config(
    request: PortForwardRequest,
    current_user: User = Depends(get_current_user)
):
    """Creates a simple port forwarding configuration without SSL."""
    configs = await load_configs()
    
    if any(c.id == request.id for c in configs):
        raise HTTPException(status_code=409, detail=f"Config with ID '{request.id}' already exists")

    # Create location for port forwarding
    location = ProxyLocation(
        path=request.path,
        backend=request.backend,
        websocket=False,
        ssl_verify=False,
        custom_headers={},
        rate_limit=None,
        auth_basic=None,
        client_max_body_size="1m"
    )

    # Create server config for port forwarding
    config = ServerConfig(
        id=request.id,
        server_name=None,  # No server name for port forwarding
        listen_port=request.listen_port,
        locations=[location],
        upstream=None,
        is_active=True,
        rate_limit_global=None,
        access_log_enabled=True,
        error_log_enabled=True,
        gzip_enabled=False,  # Disable gzip for port forwarding
        security_headers=False,  # Disable security headers for port forwarding
        port_forward_only=True,
        ssl_cert=None,  # No SSL for port forwarding
        ssl_key=None,  # No SSL for port forwarding
        created_by=current_user.username
    )
    
    configs.append(config)
    await save_configs(configs)
    await apply_nginx_config(config)
    logger.info(f"Port forward config created by {current_user.username}: {request.id}")
    return config

@app.put("/api/configs/{config_id}", response_model=ServerConfig)
async def update_config(config_id: str, updated_config: ServerConfigForm, current_user: User = Depends(get_current_user)):
    """Updates an existing configuration."""
    if config_id != updated_config.id:
        raise HTTPException(status_code=400, detail="Config ID in path doesn't match request body")
    
    configs = await load_configs()
    for i, config in enumerate(configs):
        if config.id == config_id:
            if current_user.role != "admin" and config.created_by != current_user.username:
                raise HTTPException(status_code=403, detail="You can only edit your own configurations")
            
            # Handle SSL certificate content if provided
            ssl_cert_path = None
            ssl_key_path = None
            
            if updated_config.ssl_cert_content and updated_config.ssl_key_content:
                # Create SSL certificate files
                ssl_dir = Path("/etc/ssl/custom")
                ssl_dir.mkdir(parents=True, exist_ok=True)
                
                ssl_cert_path = ssl_dir / f"{config_id}.crt"
                ssl_key_path = ssl_dir / f"{config_id}.key"
                
                try:
                    # Write certificate content to files
                    async with aiofiles.open(ssl_cert_path, 'w') as f:
                        await f.write(updated_config.ssl_cert_content)
                    async with aiofiles.open(ssl_key_path, 'w') as f:
                        await f.write(updated_config.ssl_key_content)
                    
                    # Set proper permissions
                    run_command(["chmod", "644", str(ssl_cert_path)])
                    run_command(["chmod", "600", str(ssl_key_path)])
                    
                except Exception as e:
                    logger.error(f"Failed to write SSL certificate files: {e}")
                    raise HTTPException(status_code=500, detail="Failed to create SSL certificate files")
            
            # Convert form data to ServerConfig
            server_config = ServerConfig(
                id=updated_config.id,
                server_name=updated_config.server_name,
                listen_port=updated_config.listen_port,
                locations=[ProxyLocation(**loc.model_dump()) for loc in updated_config.locations],
                upstream=updated_config.upstream,
                is_active=updated_config.is_active,
                rate_limit_global=updated_config.rate_limit_global,
                access_log_enabled=updated_config.access_log_enabled,
                error_log_enabled=updated_config.error_log_enabled,
                gzip_enabled=updated_config.gzip_enabled,
                security_headers=updated_config.security_headers,
                port_forward_only=updated_config.port_forward_only,
                ssl_cert=str(ssl_cert_path) if ssl_cert_path else updated_config.ssl_cert,
                ssl_key=str(ssl_key_path) if ssl_key_path else updated_config.ssl_key,
                created_at=config.created_at,
                created_by=config.created_by,
                updated_at=datetime.utcnow().isoformat()
            )
            
            # Set default SSL certificate paths for domain-based configs if no custom SSL provided
            if not updated_config.port_forward_only and updated_config.server_name and not ssl_cert_path:
                server_config.ssl_cert = str(DEFAULT_SSL_CERT)
                server_config.ssl_key = str(DEFAULT_SSL_KEY)
            
            configs[i] = server_config
            await save_configs(configs)
            await apply_nginx_config(server_config)
            logger.info(f"Config updated by {current_user.username}: {config_id}")
            return server_config
    
    raise HTTPException(status_code=404, detail=f"Config with ID '{config_id}' not found")

@app.delete("/api/configs/{config_id}")
async def delete_config(config_id: str, current_user: User = Depends(get_current_user)):
    """Deletes a configuration."""
    configs = await load_configs()
    config_to_delete = None
    
    for config in configs:
        if config.id == config_id:
            config_to_delete = config
            break
    
    if not config_to_delete:
        raise HTTPException(status_code=404, detail=f"Config with ID '{config_id}' not found")
    
    if current_user.role != "admin" and config_to_delete.created_by != current_user.username:
        raise HTTPException(status_code=403, detail="You can only delete your own configurations")
    
    configs = [c for c in configs if c.id != config_id]
    await save_configs(configs)
    
    config_file = NGINX_SITES_AVAILABLE / f"{config_id}.conf"
    enabled_link = NGINX_SITES_ENABLED / f"{config_id}.conf"
    
    with contextlib.suppress(FileNotFoundError):
        if enabled_link.exists():
            enabled_link.unlink()
        if config_file.exists():
            config_file.unlink()
    
    try:
        run_command(["nginx", "-t"])
        run_command(["systemctl", "reload", "nginx"])
    except Exception as e:
        logger.error(f"Nginx reload failed after deletion: {e}")
    
    logger.info(f"Config deleted by {current_user.username}: {config_id}")
    return {"message": f"Config '{config_id}' deleted"}

@app.post("/api/configs/{config_id}/toggle", response_model=ServerConfig)
async def toggle_config_status(config_id: str, current_user: User = Depends(get_current_user)):
    """Toggles configuration active status."""
    configs = await load_configs()
    for i, config in enumerate(configs):
        if config.id == config_id:
            config.is_active = not config.is_active
            config.updated_at = datetime.utcnow().isoformat()
            await save_configs(configs)
            await apply_nginx_config(config)
            logger.info(f"Config {'enabled' if config.is_active else 'disabled'}: {config_id}")
            return config
    raise HTTPException(status_code=404, detail=f"Config with ID '{config_id}' not found")

@app.post("/api/configs/{config_id}/test")
async def test_config(config_id: str, current_user: User = Depends(get_current_user)):
    """Tests a specific configuration."""
    configs = await load_configs()
    config = next((c for c in configs if c.id == config_id), None)
    if not config:
        raise HTTPException(status_code=404, detail=f"Config with ID '{config_id}' not found")
    
    try:
        temp_config = f"/tmp/nginx_test_{config_id}.conf"
        config_content = generate_nginx_config_content(config)
        
        with open(temp_config, 'w') as f:
            f.write(config_content)
        
        result = run_command(["nginx", "-t", "-c", temp_config])
        
        os.unlink(temp_config)
        
        return {"success": True, "message": "Configuration test passed"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/configs/validate")
async def validate_config(config: ServerConfigForm, current_user: User = Depends(get_current_user)):
    """Validates a configuration before saving."""
    try:
        # Convert form data to ServerConfig for validation
        server_config = ServerConfig(
            id=config.id,
            server_name=config.server_name,
            listen_port=config.listen_port,
            locations=[ProxyLocation(**loc.model_dump()) for loc in config.locations],
            upstream=config.upstream,
            is_active=config.is_active,
            rate_limit_global=config.rate_limit_global,
            access_log_enabled=config.access_log_enabled,
            error_log_enabled=config.error_log_enabled,
            gzip_enabled=config.gzip_enabled,
            security_headers=config.security_headers,
            port_forward_only=config.port_forward_only,
            ssl_cert=config.ssl_cert,
            ssl_key=config.ssl_key
        )
        
        # Generate nginx config to test syntax
        config_content = generate_nginx_config_content(server_config)
        temp_config = f"/tmp/nginx_validate_{config.id}.conf"
        
        with open(temp_config, 'w') as f:
            f.write(config_content)
        
        result = run_command(["nginx", "-t", "-c", temp_config])
        os.unlink(temp_config)
        
        return {
            "success": True,
            "message": "Configuration is valid",
            "config_preview": config_content
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Configuration validation failed"
        }

@app.get("/api/configs/{config_id}/metrics")
async def get_config_metrics(config_id: str, current_user: User = Depends(get_current_user)):
    """Get metrics for a specific configuration."""
    configs = await load_configs()
    config = next((c for c in configs if c.id == config_id), None)
    if not config:
        raise HTTPException(status_code=404, detail=f"Config with ID '{config_id}' not found")
    
    try:
        # Get access log file path
        access_log_file = LOG_FILE_NGINX_ACCESS_PREFIX / f"{config_id}_access.log"
        
        # Basic metrics (you can expand this with more sophisticated metrics)
        metrics = {
            "config_id": config_id,
            "server_name": config.server_name,
            "listen_port": config.listen_port,
            "is_active": config.is_active,
            "locations_count": len(config.locations),
            "has_upstream": config.upstream is not None,
            "has_rate_limit": config.rate_limit_global is not None,
            "port_forward_only": config.port_forward_only,
            "created_at": config.created_at,
            "updated_at": config.updated_at,
            "access_log_file": str(access_log_file) if access_log_file.exists() else None,
            "nginx_status": "active" if config.is_active else "inactive"
        }
        
        # Try to get basic log statistics if log file exists
        if access_log_file.exists():
            try:
                # Count lines in access log (basic request count)
                with open(access_log_file, 'r') as f:
                    line_count = sum(1 for _ in f)
                metrics["total_requests"] = line_count
                
                # Get file size
                metrics["log_file_size"] = access_log_file.stat().st_size
                
                # Get last modified time
                metrics["last_activity"] = datetime.fromtimestamp(access_log_file.stat().st_mtime).isoformat()
                
            except Exception as e:
                logger.warning(f"Could not read metrics from log file: {e}")
                metrics["total_requests"] = 0
                metrics["log_file_size"] = 0
                metrics["last_activity"] = None
        else:
            metrics["total_requests"] = 0
            metrics["log_file_size"] = 0
            metrics["last_activity"] = None
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to get metrics for config {config_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/system/status", response_model=SystemStats)
async def get_system_status(current_user: User = Depends(get_current_user)):
    """Get system status and statistics."""
    return get_system_stats()

@app.post("/api/system/nginx/restart")
async def restart_nginx(current_user: User = Depends(require_admin)):
    """Restart Nginx service (Admin only)."""
    try:
        run_command(["systemctl", "restart", "nginx"])
        logger.info(f"Nginx restarted by {current_user.username}")
        return {"message": "Nginx restarted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restart Nginx: {str(e)}")

@app.post("/api/system/nginx/reload")
async def reload_nginx(current_user: User = Depends(require_admin)):
    """Reload Nginx configuration (Admin only)."""
    try:
        run_command(["nginx", "-t"])
        run_command(["systemctl", "reload", "nginx"])
        logger.info(f"Nginx reloaded by {current_user.username}")
        return {"message": "Nginx configuration reloaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload Nginx: {str(e)}")

@app.get("/api/system/nginx/logs")
async def get_nginx_logs(current_user: User = Depends(require_admin)):
    """Get Nginx logs (Admin only)."""
    try:
        # Get recent nginx error logs
        error_logs = run_command(["tail", "-n", "50", "/var/log/nginx/error.log"])
        
        # Get recent nginx access logs
        access_logs = run_command(["tail", "-n", "50", "/var/log/nginx/access.log"])
        
        return {
            "error_logs": error_logs.split('\n'),
            "access_logs": access_logs.split('\n'),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get nginx logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get nginx logs: {str(e)}")

# --- Backup & Restore Endpoints ---
@app.get("/api/backup/list")
async def list_backups(current_user: User = Depends(get_current_user)):
    """List all available backups."""
    try:
        backup_files = []
        if BACKUP_DIR.exists():
            for backup_file in BACKUP_DIR.glob("*.tar.gz"):
                stat = backup_file.stat()
                backup_files.append(BackupInfo(
                    filename=backup_file.name,
                    created_at=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    size=stat.st_size,
                    config_count=0  # TODO: Extract config count from backup
                ))
        
        return {"backups": backup_files}
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")

@app.post("/api/backup/create")
async def create_backup(
    request: BackupRequest,
    current_user: User = Depends(require_admin)
):
    """Create a new backup."""
    try:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"vps-manager-backup_{timestamp}.tar.gz"
        backup_path = BACKUP_DIR / backup_filename
        
        # Create backup directory if it doesn't exist
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create temporary directory for backup contents
        temp_dir = Path("/tmp/vps-manager-backup")
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Backup configurations
            if request.include_configs:
                if CONFIG_DB.exists():
                    run_command(["cp", str(CONFIG_DB), str(temp_dir / "config_db.json")])
            
            # Backup logs
            if request.include_logs and LOG_DIR.exists():
                run_command(["cp", "-r", str(LOG_DIR), str(temp_dir / "logs")])
            
            # Backup SSL certificates
            if request.include_ssl:
                ssl_backup_dir = temp_dir / "ssl"
                ssl_backup_dir.mkdir(exist_ok=True)
                
                # Backup Let's Encrypt certificates
                if LETSENCRYPT_DIR.exists():
                    run_command(["cp", "-r", str(LETSENCRYPT_DIR), str(ssl_backup_dir / "letsencrypt")])
                
                # Backup custom SSL certificates
                if DEFAULT_SSL_CERT.exists():
                    run_command(["cp", str(DEFAULT_SSL_CERT), str(ssl_backup_dir / "default.crt")])
                if DEFAULT_SSL_KEY.exists():
                    run_command(["cp", str(DEFAULT_SSL_KEY), str(ssl_backup_dir / "default.key")])
            
            # Create backup metadata
            metadata = {
                "created_at": datetime.utcnow().isoformat(),
                "created_by": current_user.username,
                "description": request.description,
                "include_configs": request.include_configs,
                "include_logs": request.include_logs,
                "include_ssl": request.include_ssl
            }
            
            with open(temp_dir / "metadata.json", "w") as f:
                json.dump(metadata, f, indent=2)
            
            # Create tar.gz archive
            run_command(["tar", "-czf", str(backup_path), "-C", str(temp_dir.parent), temp_dir.name])
            
            logger.info(f"Backup created by {current_user.username}: {backup_filename}")
            return {"message": "Backup created successfully", "filename": backup_filename}
            
        finally:
            # Clean up temporary directory
            run_command(["rm", "-rf", str(temp_dir)])
            
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create backup: {str(e)}")

@app.get("/api/backup/download/{filename}")
async def download_backup(
    filename: str,
    current_user: User = Depends(require_admin)
):
    """Download a backup file."""
    try:
        backup_path = BACKUP_DIR / filename
        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        return FileResponse(
            path=str(backup_path),
            filename=filename,
            media_type="application/gzip"
        )
    except Exception as e:
        logger.error(f"Failed to download backup {filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to download backup: {str(e)}")

@app.post("/api/backup/restore/{filename}")
async def restore_backup(
    filename: str,
    request: RestoreRequest,
    current_user: User = Depends(require_admin)
):
    """Restore from a backup file."""
    try:
        backup_path = BACKUP_DIR / filename
        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        # Create temporary directory for extraction
        temp_dir = Path("/tmp/vps-manager-restore")
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Extract backup
            run_command(["tar", "-xzf", str(backup_path), "-C", str(temp_dir)])
            
            # Find the extracted directory
            extracted_dirs = list(temp_dir.iterdir())
            if not extracted_dirs:
                raise HTTPException(status_code=400, detail="Invalid backup file format")
            
            extracted_dir = extracted_dirs[0]
            
            # Read metadata
            metadata_file = extracted_dir / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file, "r") as f:
                    metadata = json.load(f)
            else:
                metadata = {}
            
            # Restore configurations
            if metadata.get("include_configs", True):
                config_file = extracted_dir / "config_db.json"
                if config_file.exists():
                    if request.overwrite_existing or not CONFIG_DB.exists():
                        run_command(["cp", str(config_file), str(CONFIG_DB)])
                        logger.info("Configuration restored from backup")
            
            # Restore logs
            if metadata.get("include_logs", False):
                logs_dir = extracted_dir / "logs"
                if logs_dir.exists():
                    run_command(["cp", "-r", str(logs_dir), str(LOG_DIR.parent)])
                    logger.info("Logs restored from backup")
            
            # Restore SSL certificates
            if metadata.get("include_ssl", True):
                ssl_dir = extracted_dir / "ssl"
                if ssl_dir.exists():
                    # Restore Let's Encrypt certificates
                    letsencrypt_backup = ssl_dir / "letsencrypt"
                    if letsencrypt_backup.exists():
                        run_command(["cp", "-r", str(letsencrypt_backup), str(LETSENCRYPT_DIR.parent)])
                    
                    # Restore custom certificates
                    default_cert = ssl_dir / "default.crt"
                    default_key = ssl_dir / "default.key"
                    if default_cert.exists():
                        run_command(["cp", str(default_cert), str(DEFAULT_SSL_CERT)])
                    if default_key.exists():
                        run_command(["cp", str(default_key), str(DEFAULT_SSL_KEY)])
                    
                    logger.info("SSL certificates restored from backup")
            
            # Reload nginx configuration
            run_command(["nginx", "-t"])
            run_command(["systemctl", "reload", "nginx"])
            
            logger.info(f"Backup restored by {current_user.username}: {filename}")
            return {"message": "Backup restored successfully"}
            
        finally:
            # Clean up temporary directory
            run_command(["rm", "-rf", str(temp_dir)])
            
    except Exception as e:
        logger.error(f"Failed to restore backup {filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to restore backup: {str(e)}")

@app.delete("/api/backup/delete/{filename}")
async def delete_backup(
    filename: str,
    current_user: User = Depends(require_admin)
):
    """Delete a backup file."""
    try:
        backup_path = BACKUP_DIR / filename
        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        backup_path.unlink()
        logger.info(f"Backup deleted by {current_user.username}: {filename}")
        return {"message": "Backup deleted successfully"}
    except Exception as e:
        logger.error(f"Failed to delete backup {filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete backup: {str(e)}")

# --- SSL Manager Endpoints ---
@app.get("/api/ssl/certificates")
async def list_ssl_certificates(current_user: User = Depends(get_current_user)):
    """List all SSL certificates."""
    try:
        certificates = []
        
        # Check Let's Encrypt certificates
        if LETSENCRYPT_DIR.exists():
            for cert_dir in LETSENCRYPT_DIR.iterdir():
                if cert_dir.is_dir():
                    cert_file = cert_dir / "cert.pem"
                    if cert_file.exists():
                        try:
                            # Get certificate info
                            result = run_command([
                                "openssl", "x509", "-in", str(cert_file), 
                                "-noout", "-subject", "-issuer", "-dates"
                            ])
                            
                            # Parse certificate info
                            lines = result.split('\n')
                            subject = ""
                            issuer = ""
                            not_after = ""
                            
                            for line in lines:
                                if line.startswith("subject="):
                                    subject = line.split("=", 1)[1]
                                elif line.startswith("issuer="):
                                    issuer = line.split("=", 1)[1]
                                elif line.startswith("notAfter="):
                                    not_after = line.split("=", 1)[1]
                            
                            # Determine status
                            if not_after:
                                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_until_expiry = (expiry_date - datetime.utcnow()).days
                                
                                if days_until_expiry < 0:
                                    status = "expired"
                                elif days_until_expiry < 30:
                                    status = "expiring"
                                else:
                                    status = "valid"
                            else:
                                status = "unknown"
                            
                            certificates.append(SSLCertificate(
                                domain=cert_dir.name,
                                issuer="Let's Encrypt" if "Let's Encrypt" in issuer else "Custom CA",
                                expires=not_after,
                                status=status,
                                auto_renew=True,
                                cert_path=str(cert_file),
                                key_path=str(cert_dir / "privkey.pem")
                            ))
                        except Exception as e:
                            logger.warning(f"Could not read certificate {cert_dir.name}: {e}")
        
        # Check default certificate
        if DEFAULT_SSL_CERT.exists() and DEFAULT_SSL_KEY.exists():
            try:
                result = run_command([
                    "openssl", "x509", "-in", str(DEFAULT_SSL_CERT), 
                    "-noout", "-subject", "-issuer", "-dates"
                ])
                
                lines = result.split('\n')
                subject = ""
                issuer = ""
                not_after = ""
                
                for line in lines:
                    if line.startswith("subject="):
                        subject = line.split("=", 1)[1]
                    elif line.startswith("issuer="):
                        issuer = line.split("=", 1)[1]
                    elif line.startswith("notAfter="):
                        not_after = line.split("=", 1)[1]
                
                if not_after:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (expiry_date - datetime.utcnow()).days
                    
                    if days_until_expiry < 0:
                        status = "expired"
                    elif days_until_expiry < 30:
                        status = "expiring"
                    else:
                        status = "valid"
                else:
                    status = "unknown"
                
                certificates.append(SSLCertificate(
                    domain="*.ptsi.co.id",
                    issuer="Custom CA",
                    expires=not_after,
                    status=status,
                    auto_renew=False,
                    cert_path=str(DEFAULT_SSL_CERT),
                    key_path=str(DEFAULT_SSL_KEY)
                ))
            except Exception as e:
                logger.warning(f"Could not read default certificate: {e}")
        
        return {"certificates": certificates}
    except Exception as e:
        logger.error(f"Failed to list SSL certificates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list SSL certificates: {str(e)}")

@app.post("/api/ssl/request-letsencrypt")
async def request_letsencrypt_certificate(
    domain: str,
    current_user: User = Depends(require_admin)
):
    """Request a new Let's Encrypt certificate."""
    try:
        # Validate domain
        if not domain or "." not in domain:
            raise HTTPException(status_code=400, detail="Invalid domain name")
        
        # Check if certbot is available
        try:
            run_command(["which", "certbot"])
        except:
            raise HTTPException(status_code=500, detail="Certbot is not installed")
        
        # Request certificate
        run_command([
            "certbot", "certonly", "--webroot", 
            "--webroot-path=/var/www/html",
            "--email=admin@ptsi.co.id",
            "--agree-tos",
            "--non-interactive",
            "--domains", domain
        ])
        
        logger.info(f"Let's Encrypt certificate requested for {domain} by {current_user.username}")
        return {"message": f"Certificate requested successfully for {domain}"}
    except Exception as e:
        logger.error(f"Failed to request Let's Encrypt certificate for {domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to request certificate: {str(e)}")

@app.post("/api/ssl/renew/{domain}")
async def renew_ssl_certificate(
    domain: str,
    current_user: User = Depends(require_admin)
):
    """Renew an SSL certificate."""
    try:
        # Check if certbot is available
        try:
            run_command(["which", "certbot"])
        except:
            raise HTTPException(status_code=500, detail="Certbot is not installed")
        
        # Renew certificate
        run_command(["certbot", "renew", "--cert-name", domain])
        
        # Reload nginx
        run_command(["systemctl", "reload", "nginx"])
        
        logger.info(f"SSL certificate renewed for {domain} by {current_user.username}")
        return {"message": f"Certificate renewed successfully for {domain}"}
    except Exception as e:
        logger.error(f"Failed to renew SSL certificate for {domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to renew certificate: {str(e)}")

@app.post("/api/ssl/upload")
async def upload_ssl_certificate(
    request: SSLUploadRequest,
    current_user: User = Depends(require_admin)
):
    """Upload custom SSL certificate."""
    try:
        # Create SSL directory
        ssl_dir = Path("/etc/ssl/custom")
        ssl_dir.mkdir(parents=True, exist_ok=True)
        
        # Create certificate files
        cert_path = ssl_dir / f"{request.domain}.crt"
        key_path = ssl_dir / f"{request.domain}.key"
        
        # Write certificate content
        async with aiofiles.open(cert_path, 'w') as f:
            await f.write(request.cert_content)
        async with aiofiles.open(key_path, 'w') as f:
            await f.write(request.key_content)
        
        # Set proper permissions
        run_command(["chmod", "644", str(cert_path)])
        run_command(["chmod", "600", str(key_path)])
        
        logger.info(f"SSL certificate uploaded for {request.domain} by {current_user.username}")
        return {
            "message": "SSL certificate uploaded successfully",
            "cert_path": str(cert_path),
            "key_path": str(key_path)
        }
    except Exception as e:
        logger.error(f"Failed to upload SSL certificate: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to upload SSL certificate: {str(e)}")

@app.get("/api/ssl/certificate/{domain}/content")
async def get_ssl_certificate_content(
    domain: str,
    current_user: User = Depends(get_current_user)
):
    """Get SSL certificate content for a domain."""
    try:
        # Check custom certificates first
        custom_cert_path = Path(f"/etc/ssl/custom/{domain}.crt")
        custom_key_path = Path(f"/etc/ssl/custom/{domain}.key")
        
        if custom_cert_path.exists() and custom_key_path.exists():
            async with aiofiles.open(custom_cert_path, 'r') as f:
                cert_content = await f.read()
            async with aiofiles.open(custom_key_path, 'r') as f:
                key_content = await f.read()
            
            return {
                "domain": domain,
                "cert_content": cert_content,
                "key_content": key_content,
                "source": "custom"
            }
        
        # Check Let's Encrypt certificates
        letsencrypt_cert_path = LETSENCRYPT_DIR / domain / "cert.pem"
        letsencrypt_key_path = LETSENCRYPT_DIR / domain / "privkey.pem"
        
        if letsencrypt_cert_path.exists() and letsencrypt_key_path.exists():
            async with aiofiles.open(letsencrypt_cert_path, 'r') as f:
                cert_content = await f.read()
            async with aiofiles.open(letsencrypt_key_path, 'r') as f:
                key_content = await f.read()
            
            return {
                "domain": domain,
                "cert_content": cert_content,
                "key_content": key_content,
                "source": "letsencrypt"
            }
        
        raise HTTPException(status_code=404, detail=f"SSL certificate not found for domain {domain}")
    except Exception as e:
        logger.error(f"Failed to get SSL certificate content for {domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get SSL certificate content: {str(e)}")

@app.get("/api/ssl/domains")
async def get_ssl_domains(current_user: User = Depends(get_current_user)):
    """Get list of domains with SSL certificates."""
    try:
        domains = []
        
        # Get custom certificates
        custom_ssl_dir = Path("/etc/ssl/custom")
        if custom_ssl_dir.exists():
            for cert_file in custom_ssl_dir.glob("*.crt"):
                domain = cert_file.stem
                domains.append({
                    "domain": domain,
                    "source": "custom",
                    "cert_path": str(cert_file),
                    "key_path": str(cert_file.with_suffix(".key"))
                })
        
        # Get Let's Encrypt certificates
        if LETSENCRYPT_DIR.exists():
            for cert_dir in LETSENCRYPT_DIR.iterdir():
                if cert_dir.is_dir():
                    cert_file = cert_dir / "cert.pem"
                    key_file = cert_dir / "privkey.pem"
                    if cert_file.exists() and key_file.exists():
                        domains.append({
                            "domain": cert_dir.name,
                            "source": "letsencrypt",
                            "cert_path": str(cert_file),
                            "key_path": str(key_file)
                        })
        
        return {"domains": domains}
    except Exception as e:
        logger.error(f"Failed to get SSL domains: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get SSL domains: {str(e)}")

# --- Load Balancer Endpoints ---
@app.get("/api/load-balancer/pools")
async def list_load_balancer_pools(current_user: User = Depends(get_current_user)):
    """List all load balancer pools."""
    try:
        # For now, return mock data. In a real implementation, this would read from a database
        pools = [
            {
                "name": "web_backend",
                "method": "round_robin",
                "health_check": True,
                "created_at": datetime.utcnow().isoformat(),
                "servers": [
                    {
                        "address": "192.168.1.10:3000",
                        "weight": 1,
                        "status": "up",
                        "max_fails": 3,
                        "fail_timeout": "30s"
                    },
                    {
                        "address": "192.168.1.11:3000",
                        "weight": 1,
                        "status": "up",
                        "max_fails": 3,
                        "fail_timeout": "30s"
                    }
                ]
            }
        ]
        
        return {"pools": pools}
    except Exception as e:
        logger.error(f"Failed to list load balancer pools: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list load balancer pools: {str(e)}")

@app.post("/api/load-balancer/pools")
async def create_load_balancer_pool(
    pool: LoadBalancerPool,
    current_user: User = Depends(require_admin)
):
    """Create a new load balancer pool."""
    try:
        # Validate pool name
        if not pool.name or not pool.name.replace('_', '').replace('-', '').isalnum():
            raise HTTPException(status_code=400, detail="Invalid pool name")
        
        # Validate method
        if pool.method not in ["round_robin", "least_conn", "ip_hash"]:
            raise HTTPException(status_code=400, detail="Invalid load balancing method")
        
        # Validate servers
        for server in pool.servers:
            if "address" not in server:
                raise HTTPException(status_code=400, detail="Server address is required")
        
        # In a real implementation, save to database
        logger.info(f"Load balancer pool created by {current_user.username}: {pool.name}")
        return {"message": "Load balancer pool created successfully", "pool": pool}
    except Exception as e:
        logger.error(f"Failed to create load balancer pool: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create load balancer pool: {str(e)}")

# --- Config Templates Endpoints ---
@app.get("/api/templates")
async def list_config_templates(current_user: User = Depends(get_current_user)):
    """List all configuration templates."""
    try:
        templates = [
            {
                "name": "Basic Web App",
                "description": "Simple reverse proxy for web applications with basic security headers",
                "category": "web",
                "config": {
                    "listen_port": 80,
                    "security_headers": True,
                    "gzip_enabled": True,
                    "locations": [
                        {
                            "path": "/",
                            "backend": "127.0.0.1:3000",
                            "websocket": False,
                            "ssl_verify": True
                        }
                    ]
                }
            },
            {
                "name": "API Gateway",
                "description": "API gateway with rate limiting and CORS support",
                "category": "api",
                "config": {
                    "listen_port": 80,
                    "rate_limit_global": "100r/m",
                    "security_headers": True,
                    "locations": [
                        {
                            "path": "/api/",
                            "backend": "127.0.0.1:8080",
                            "rate_limit": "10r/s",
                            "custom_headers": {
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
                            }
                        }
                    ]
                }
            },
            {
                "name": "WebSocket Application",
                "description": "WebSocket application with upgrade support and connection handling",
                "category": "websocket",
                "config": {
                    "listen_port": 80,
                    "locations": [
                        {
                            "path": "/",
                            "backend": "127.0.0.1:3000",
                            "websocket": True,
                            "proxy_http_version": "1.1"
                        }
                    ]
                }
            },
            {
                "name": "Load Balanced App",
                "description": "Load balanced application with multiple backend servers",
                "category": "load-balancer",
                "config": {
                    "listen_port": 80,
                    "upstream": {
                        "name": "app_backend",
                        "method": "round_robin",
                        "health_check": True,
                        "servers": ["127.0.0.1:3000", "127.0.0.1:3001", "127.0.0.1:3002"]
                    },
                    "locations": [
                        {
                            "path": "/",
                            "backend": "app_backend"
                        }
                    ]
                }
            }
        ]
        
        return {"templates": templates}
    except Exception as e:
        logger.error(f"Failed to list config templates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list config templates: {str(e)}")

# --- Log Viewer Endpoints ---
@app.get("/api/logs/nginx")
async def get_nginx_logs(
    log_type: str = "error",
    lines: int = 100,
    current_user: User = Depends(get_current_user)
):
    """Get Nginx logs."""
    try:
        if log_type == "error":
            log_file = "/var/log/nginx/error.log"
        elif log_type == "access":
            log_file = "/var/log/nginx/access.log"
        else:
            raise HTTPException(status_code=400, detail="Invalid log type")
        
        if not Path(log_file).exists():
            return {"logs": [], "message": "Log file not found"}
        
        result = run_command(["tail", "-n", str(lines), log_file])
        logs = result.split('\n') if result else []
        
        return {"logs": logs, "log_type": log_type, "lines": len(logs)}
    except Exception as e:
        logger.error(f"Failed to get nginx logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get nginx logs: {str(e)}")

@app.get("/api/logs/application")
async def get_application_logs(
    lines: int = 100,
    current_user: User = Depends(get_current_user)
):
    """Get application logs."""
    try:
        log_file = LOG_FILE_APP
        if not log_file.exists():
            return {"logs": [], "message": "Log file not found"}
        
        result = run_command(["tail", "-n", str(lines), str(log_file)])
        logs = result.split('\n') if result else []
        
        return {"logs": logs, "lines": len(logs)}
    except Exception as e:
        logger.error(f"Failed to get application logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get application logs: {str(e)}")

@app.get("/api/logs/system")
async def get_system_logs(
    lines: int = 100,
    current_user: User = Depends(require_admin)
):
    """Get system logs."""
    try:
        result = run_command(["journalctl", "-n", str(lines), "--no-pager"])
        logs = result.split('\n') if result else []
        
        return {"logs": logs, "lines": len(logs)}
    except Exception as e:
        logger.error(f"Failed to get system logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get system logs: {str(e)}")

# --- Advanced Logging Endpoints ---
@app.get("/api/logs/structured")
async def get_structured_logs(
    filter: LogFilter = Depends(),
    current_user: User = Depends(get_current_user)
):
    """Get structured logs with filtering."""
    try:
        # Read structured logs from file
        log_file = LOG_DIR / "structured.log"
        if not log_file.exists():
            return {"logs": [], "total": 0}
        
        logs = []
        with open(log_file, "r") as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    
                    # Apply filters
                    if filter.level and log_entry.get("level") != filter.level:
                        continue
                    if filter.source and log_entry.get("source") != filter.source:
                        continue
                    if filter.user_id and log_entry.get("user_id") != filter.user_id:
                        continue
                    if filter.action and log_entry.get("action") != filter.action:
                        continue
                    
                    # Time filter
                    if filter.start_time or filter.end_time:
                        log_time = datetime.fromisoformat(log_entry.get("timestamp", ""))
                        if filter.start_time:
                            start_time = datetime.fromisoformat(filter.start_time)
                            if log_time < start_time:
                                continue
                        if filter.end_time:
                            end_time = datetime.fromisoformat(filter.end_time)
                            if log_time > end_time:
                                continue
                    
                    logs.append(log_entry)
                    
                    if len(logs) >= filter.limit:
                        break
                        
                except json.JSONDecodeError:
                    continue
        
        return {"logs": logs, "total": len(logs)}
    except Exception as e:
        logger.error(f"Failed to get structured logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get structured logs: {str(e)}")

@app.get("/api/logs/audit")
async def get_audit_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 1000,
    current_user: User = Depends(require_admin)
):
    """Get audit logs for compliance."""
    try:
        audit_log_file = LOG_DIR / "audit.log"
        if not audit_log_file.exists():
            return {"logs": [], "total": 0}
        
        logs = []
        with open(audit_log_file, "r") as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    
                    # Apply filters
                    if user_id and log_entry.get("user_id") != user_id:
                        continue
                    if action and log_entry.get("action") != action:
                        continue
                    
                    # Time filter
                    if start_time or end_time:
                        log_time = datetime.fromisoformat(log_entry.get("timestamp", ""))
                        if start_time:
                            start = datetime.fromisoformat(start_time)
                            if log_time < start:
                                continue
                        if end_time:
                            end = datetime.fromisoformat(end_time)
                            if log_time > end:
                                continue
                    
                    logs.append(log_entry)
                    
                    if len(logs) >= limit:
                        break
                        
                except json.JSONDecodeError:
                    continue
        
        return {"logs": logs, "total": len(logs)}
    except Exception as e:
        logger.error(f"Failed to get audit logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get audit logs: {str(e)}")

@app.get("/api/logs/performance")
async def get_performance_logs(
    operation: Optional[str] = None,
    min_duration: Optional[float] = None,
    max_duration: Optional[float] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 1000,
    current_user: User = Depends(get_current_user)
):
    """Get performance logs."""
    try:
        perf_log_file = LOG_DIR / "performance.log"
        if not perf_log_file.exists():
            return {"logs": [], "total": 0}
        
        logs = []
        with open(perf_log_file, "r") as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    
                    # Apply filters
                    if operation and log_entry.get("operation") != operation:
                        continue
                    if min_duration and log_entry.get("duration_ms", 0) < min_duration:
                        continue
                    if max_duration and log_entry.get("duration_ms", 0) > max_duration:
                        continue
                    
                    # Time filter
                    if start_time or end_time:
                        log_time = datetime.fromisoformat(log_entry.get("timestamp", ""))
                        if start_time:
                            start = datetime.fromisoformat(start_time)
                            if log_time < start:
                                continue
                        if end_time:
                            end = datetime.fromisoformat(end_time)
                            if log_time > end:
                                continue
                    
                    logs.append(log_entry)
                    
                    if len(logs) >= limit:
                        break
                        
                except json.JSONDecodeError:
                    continue
        
        return {"logs": logs, "total": len(logs)}
    except Exception as e:
        logger.error(f"Failed to get performance logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance logs: {str(e)}")

@app.get("/api/logs/security")
async def get_security_logs(
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    user_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 1000,
    current_user: User = Depends(require_admin)
):
    """Get security logs."""
    try:
        security_log_file = LOG_DIR / "security.log"
        if not security_log_file.exists():
            return {"logs": [], "total": 0}
        
        logs = []
        with open(security_log_file, "r") as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    
                    # Apply filters
                    if severity and log_entry.get("severity") != severity:
                        continue
                    if event_type and log_entry.get("event_type") != event_type:
                        continue
                    if user_id and log_entry.get("user_id") != user_id:
                        continue
                    
                    # Time filter
                    if start_time or end_time:
                        log_time = datetime.fromisoformat(log_entry.get("timestamp", ""))
                        if start_time:
                            start = datetime.fromisoformat(start_time)
                            if log_time < start:
                                continue
                        if end_time:
                            end = datetime.fromisoformat(end_time)
                            if log_time > end:
                                continue
                    
                    logs.append(log_entry)
                    
                    if len(logs) >= limit:
                        break
                        
                except json.JSONDecodeError:
                    continue
        
        return {"logs": logs, "total": len(logs)}
    except Exception as e:
        logger.error(f"Failed to get security logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get security logs: {str(e)}")

@app.get("/api/logs/retention-policy")
async def get_log_retention_policy(current_user: User = Depends(require_admin)):
    """Get current log retention policy."""
    return log_retention_policy.model_dump()

@app.put("/api/logs/retention-policy")
async def update_log_retention_policy(
    policy: LogRetentionPolicy,
    current_user: User = Depends(require_admin)
):
    """Update log retention policy."""
    global log_retention_policy
    log_retention_policy = policy
    logger.info(f"Log retention policy updated by {current_user.username}")
    return {"message": "Log retention policy updated successfully"}

@app.post("/api/logs/cleanup")
async def cleanup_old_logs(current_user: User = Depends(require_admin)):
    """Clean up old logs based on retention policy."""
    try:
        cleaned_files = 0
        
        # Clean up nginx logs
        nginx_logs = LOG_DIR.glob("nginx_*.log")
        for log_file in nginx_logs:
            file_age = datetime.utcnow() - datetime.fromtimestamp(log_file.stat().st_mtime)
            if file_age.days > log_retention_policy.nginx_logs_days:
                log_file.unlink()
                cleaned_files += 1
        
        # Clean up API logs
        api_logs = LOG_DIR.glob("api_*.log")
        for log_file in api_logs:
            file_age = datetime.utcnow() - datetime.fromtimestamp(log_file.stat().st_mtime)
            if file_age.days > log_retention_policy.api_logs_days:
                log_file.unlink()
                cleaned_files += 1
        
        # Clean up system logs
        system_logs = LOG_DIR.glob("system_*.log")
        for log_file in system_logs:
            file_age = datetime.utcnow() - datetime.fromtimestamp(log_file.stat().st_mtime)
            if file_age.days > log_retention_policy.system_logs_days:
                log_file.unlink()
                cleaned_files += 1
        
        logger.info(f"Log cleanup completed by {current_user.username}: {cleaned_files} files removed")
        return {"message": f"Log cleanup completed: {cleaned_files} files removed"}
    except Exception as e:
        logger.error(f"Failed to cleanup logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup logs: {str(e)}")

# --- Real-time Monitoring ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                self.active_connections.remove(connection)

manager = ConnectionManager()

# Metrics storage
metrics_history: List[SystemMetrics] = []
config_metrics_history: Dict[str, List[ConfigMetrics]] = {}
alert_rules: List[AlertRule] = []
active_alerts: List[Alert] = []

def collect_system_metrics() -> SystemMetrics:
    """Collect real-time system metrics."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network metrics
        net_io = psutil.net_io_counters()
        network_in = net_io.bytes_recv / 1024 / 1024  # MB
        network_out = net_io.bytes_sent / 1024 / 1024  # MB
        
        # Nginx metrics
        try:
            nginx_status = run_command(["curl", "-s", "http://localhost/nginx_status"])
            lines = nginx_status.split('\n')
            if len(lines) >= 3:
                connections = int(lines[2].split()[2])
                requests = int(lines[2].split()[2])
            else:
                connections = 0
                requests = 0
        except:
            connections = 0
            requests = 0
        
        return SystemMetrics(
            timestamp=datetime.utcnow().isoformat(),
            cpu_usage=cpu_percent,
            memory_usage=memory.percent,
            disk_usage=disk.percent,
            network_in=network_in,
            network_out=network_out,
            nginx_connections=connections,
            nginx_requests_per_second=requests
        )
    except Exception as e:
        logger.error(f"Failed to collect system metrics: {e}")
        return SystemMetrics(
            timestamp=datetime.utcnow().isoformat(),
            cpu_usage=0.0,
            memory_usage=0.0,
            disk_usage=0.0,
            network_in=0.0,
            network_out=0.0,
            nginx_connections=0,
            nginx_requests_per_second=0.0
        )

def check_alerts(metrics: SystemMetrics):
    """Check alert rules against current metrics."""
    for rule in alert_rules:
        if not rule.enabled:
            continue
            
        value = getattr(metrics, rule.metric, 0.0)
        triggered = False
        
        if rule.operator == ">":
            triggered = value > rule.threshold
        elif rule.operator == "<":
            triggered = value < rule.threshold
        elif rule.operator == ">=":
            triggered = value >= rule.threshold
        elif rule.operator == "<=":
            triggered = value <= rule.threshold
        elif rule.operator == "==":
            triggered = value == rule.threshold
            
        if triggered:
            # Check if alert already exists
            existing_alert = next((a for a in active_alerts if a.rule_id == rule.id and a.status == "active"), None)
            if not existing_alert:
                alert = Alert(
                    id=f"alert_{int(time.time())}",
                    rule_id=rule.id,
                    timestamp=datetime.utcnow().isoformat(),
                    metric=rule.metric,
                    value=value,
                    threshold=rule.threshold,
                    status="active",
                    message=f"{rule.metric} is {rule.operator} {rule.threshold} (current: {value})"
                )
                active_alerts.append(alert)
                logger.warning(f"Alert triggered: {alert.message}")
                
                # Send Telegram notification
                asyncio.create_task(telegram_notifier.send_alert_notification(alert))

# --- WebSocket Endpoints ---
@app.websocket("/ws/monitoring")
async def websocket_monitoring(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send metrics every 5 seconds
            metrics = collect_system_metrics()
            metrics_history.append(metrics)
            
            # Keep only last 1000 metrics
            if len(metrics_history) > 1000:
                metrics_history.pop(0)
            
            # Check alerts
            check_alerts(metrics)
            
            # Send data to client
            data = {
                "type": "metrics",
                "system": metrics.model_dump(),
                "alerts": [alert.model_dump() for alert in active_alerts if alert.status == "active"]
            }
            await websocket.send_text(json.dumps(data))
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- Real-time Monitoring Endpoints ---
@app.get("/api/monitoring/metrics")
async def get_current_metrics(current_user: User = Depends(get_current_user)):
    """Get current system metrics."""
    metrics = collect_system_metrics()
    return {
        "current": metrics.model_dump(),
        "history": [m.model_dump() for m in metrics_history[-100:]],  # Last 100 metrics
        "alerts": [alert.model_dump() for alert in active_alerts if alert.status == "active"]
    }

@app.get("/api/monitoring/metrics/history")
async def get_metrics_history(
    hours: int = 24,
    current_user: User = Depends(get_current_user)
):
    """Get metrics history for specified hours."""
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    filtered_metrics = [
        m for m in metrics_history 
        if datetime.fromisoformat(m.timestamp) > cutoff_time
    ]
    return {"metrics": [m.model_dump() for m in filtered_metrics]}

@app.post("/api/monitoring/alerts/rules")
async def create_alert_rule(
    rule: AlertRule,
    current_user: User = Depends(require_admin)
):
    """Create a new alert rule."""
    rule.id = f"rule_{int(time.time())}"
    alert_rules.append(rule)
    logger.info(f"Alert rule created by {current_user.username}: {rule.name}")
    return {"message": "Alert rule created successfully", "rule": rule.model_dump()}

@app.get("/api/monitoring/alerts/rules")
async def get_alert_rules(current_user: User = Depends(get_current_user)):
    """Get all alert rules."""
    return {"rules": [rule.model_dump() for rule in alert_rules]}

@app.put("/api/monitoring/alerts/rules/{rule_id}")
async def update_alert_rule(
    rule_id: str,
    updated_rule: AlertRule,
    current_user: User = Depends(require_admin)
):
    """Update an alert rule."""
    for i, rule in enumerate(alert_rules):
        if rule.id == rule_id:
            updated_rule.id = rule_id
            alert_rules[i] = updated_rule
            logger.info(f"Alert rule updated by {current_user.username}: {rule_id}")
            return {"message": "Alert rule updated successfully", "rule": updated_rule.model_dump()}
    raise HTTPException(status_code=404, detail="Alert rule not found")

@app.delete("/api/monitoring/alerts/rules/{rule_id}")
async def delete_alert_rule(
    rule_id: str,
    current_user: User = Depends(require_admin)
):
    """Delete an alert rule."""
    for i, rule in enumerate(alert_rules):
        if rule.id == rule_id:
            alert_rules.pop(i)
            logger.info(f"Alert rule deleted by {current_user.username}: {rule_id}")
            return {"message": "Alert rule deleted successfully"}
    raise HTTPException(status_code=404, detail="Alert rule not found")

@app.get("/api/monitoring/alerts")
async def get_alerts(
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get alerts with optional status filter."""
    filtered_alerts = active_alerts
    if status:
        filtered_alerts = [a for a in active_alerts if a.status == status]
    return {"alerts": [alert.model_dump() for alert in filtered_alerts]}

@app.post("/api/monitoring/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user: User = Depends(require_admin)
):
    """Resolve an alert."""
    for alert in active_alerts:
        if alert.id == alert_id:
            alert.status = "resolved"
            logger.info(f"Alert resolved by {current_user.username}: {alert_id}")
            return {"message": "Alert resolved successfully"}
    raise HTTPException(status_code=404, detail="Alert not found")

# Redis connection for distributed caching
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_available = True
except:
    redis_client = None
    redis_available = False

# In-memory cache for fallback
config_cache = TTLCache(maxsize=1000, ttl=300)  # 5 minutes TTL
metrics_cache = TTLCache(maxsize=100, ttl=60)   # 1 minute TTL

# Thread pool for CPU-intensive tasks
thread_pool = ThreadPoolExecutor(max_workers=10)

# Connection pooling for database operations
class ConnectionPool:
    def __init__(self, max_connections=20):
        self.max_connections = max_connections
        self.available_connections = []
        self.in_use_connections = []
        self.lock = threading.Lock()
    
    def get_connection(self):
        with self.lock:
            if self.available_connections:
                conn = self.available_connections.pop()
                self.in_use_connections.append(conn)
                return conn
            elif len(self.in_use_connections) < self.max_connections:
                conn = self._create_connection()
                self.in_use_connections.append(conn)
                return conn
            else:
                raise Exception("No available connections")
    
    def return_connection(self, conn):
        with self.lock:
            if conn in self.in_use_connections:
                self.in_use_connections.remove(conn)
                self.available_connections.append(conn)
    
    def _create_connection(self):
        # Mock connection creation
        return {"id": len(self.in_use_connections) + 1, "created_at": datetime.utcnow()}

# Global connection pool
connection_pool = ConnectionPool()

# Caching decorator
def cache_result(ttl_seconds=300):
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create cache key
            cache_key = f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            
            # Try Redis first
            if redis_available:
                try:
                    cached_result = redis_client.get(cache_key)
                    if cached_result:
                        return json.loads(cached_result)
                except:
                    pass
            
            # Try in-memory cache
            if cache_key in config_cache:
                return config_cache[cache_key]
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Cache result
            if redis_available:
                try:
                    redis_client.setex(cache_key, ttl_seconds, json.dumps(result))
                except:
                    pass
            
            config_cache[cache_key] = result
            return result
        return wrapper
    return decorator

# Rate limiting with Redis
def check_rate_limit_redis(client_ip: str, limit: int = 100, window: int = 3600) -> bool:
    """Check rate limit using Redis for distributed environments."""
    if not redis_available:
        return check_rate_limit(client_ip)
    
    try:
        key = f"rate_limit:{client_ip}"
        current = redis_client.get(key)
        
        if current is None:
            redis_client.setex(key, window, 1)
            return True
        elif int(current) < limit:
            redis_client.incr(key)
            return True
        else:
            return False
    except:
        return check_rate_limit(client_ip)

# Load balancer health checks
class HealthChecker:
    def __init__(self):
        self.health_status = {}
        self.lock = threading.Lock()
    
    async def check_backend_health(self, backend_url: str) -> bool:
        """Check if a backend is healthy."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"{backend_url}/health") as response:
                    return response.status == 200
        except:
            return False
    
    def update_health_status(self, backend_url: str, is_healthy: bool):
        """Update health status for a backend."""
        with self.lock:
            self.health_status[backend_url] = {
                "healthy": is_healthy,
                "last_check": datetime.utcnow().isoformat()
            }
    
    def get_healthy_backends(self, backends: List[str]) -> List[str]:
        """Get list of healthy backends."""
        with self.lock:
            return [backend for backend in backends 
                   if self.health_status.get(backend, {}).get("healthy", True)]

# Global health checker
health_checker = HealthChecker()

# Async task queue for background processing
class TaskQueue:
    def __init__(self):
        self.tasks = []
        self.lock = threading.Lock()
    
    def add_task(self, task_func, *args, **kwargs):
        """Add a task to the queue."""
        with self.lock:
            self.tasks.append({
                "func": task_func,
                "args": args,
                "kwargs": kwargs,
                "created_at": datetime.utcnow()
            })
    
    async def process_tasks(self):
        """Process tasks in the queue."""
        while True:
            with self.lock:
                if self.tasks:
                    task = self.tasks.pop(0)
                else:
                    break
            
            try:
                # Run task in thread pool
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(thread_pool, task["func"], *task["args"], **task["kwargs"])
            except Exception as e:
                logger.error(f"Task execution failed: {e}")

# Global task queue
task_queue = TaskQueue()

# Cached system stats
@cache_result(ttl_seconds=60)
def get_cached_system_stats() -> SystemStats:
    """Get cached system stats."""
    return get_system_stats()

# Horizontal scaling support
class ClusterManager:
    def __init__(self):
        self.nodes = []
        self.current_node_id = None
    
    def register_node(self, node_id: str, node_url: str, node_capacity: int = 100):
        """Register a new node in the cluster."""
        self.nodes.append({
            "id": node_id,
            "url": node_url,
            "capacity": node_capacity,
            "registered_at": datetime.utcnow().isoformat(),
            "status": "active"
        })
    
    def get_node_load(self, node_id: str) -> float:
        """Get current load for a node."""
        # Mock implementation
        return 0.5
    
    def select_best_node(self, operation: str) -> str:
        """Select the best node for an operation."""
        if not self.nodes:
            return None
        
        # Simple round-robin for now
        return self.nodes[0]["id"]
    
    def distribute_task(self, task_data: Dict[str, Any]):
        """Distribute task to appropriate node."""
        best_node = self.select_best_node(task_data.get("type", "default"))
        if best_node:
            # Send task to node
            logger.info(f"Distributing task to node {best_node}")
            return best_node
        return None

# Global cluster manager
cluster_manager = ClusterManager()

# Scalability endpoints
@app.get("/api/cluster/nodes")
async def get_cluster_nodes(current_user: User = Depends(require_admin)):
    """Get all nodes in the cluster."""
    return {
        "nodes": cluster_manager.nodes,
        "current_node": cluster_manager.current_node_id
    }

@app.post("/api/cluster/nodes")
async def register_cluster_node(
    node_data: Dict[str, Any],
    current_user: User = Depends(require_admin)
):
    """Register a new node in the cluster."""
    cluster_manager.register_node(
        node_data["id"],
        node_data["url"],
        node_data.get("capacity", 100)
    )
    return {"message": "Node registered successfully"}

@app.get("/api/cluster/load")
async def get_cluster_load(current_user: User = Depends(get_current_user)):
    """Get load distribution across cluster."""
    load_info = {}
    for node in cluster_manager.nodes:
        load_info[node["id"]] = {
            "load": cluster_manager.get_node_load(node["id"]),
            "capacity": node["capacity"],
            "status": node["status"]
        }
    return {"load_distribution": load_info}

@app.post("/api/cluster/tasks/distribute")
async def distribute_task(
    task_data: Dict[str, Any],
    current_user: User = Depends(require_admin)
):
    """Distribute a task across the cluster."""
    node_id = cluster_manager.distribute_task(task_data)
    return {"assigned_node": node_id}

# Performance monitoring
@app.get("/api/performance/cache/stats")
async def get_cache_stats(current_user: User = Depends(require_admin)):
    """Get cache statistics."""
    redis_stats = {}
    if redis_available:
        try:
            redis_stats = {
                "connected": True,
                "memory_usage": redis_client.info("memory"),
                "keys": redis_client.dbsize()
            }
        except:
            redis_stats = {"connected": False}
    
    return {
        "redis": redis_stats,
        "memory_cache": {
            "config_cache_size": len(config_cache),
            "metrics_cache_size": len(metrics_cache)
        }
    }

@app.post("/api/performance/cache/clear")
async def clear_cache(current_user: User = Depends(require_admin)):
    """Clear all caches."""
    config_cache.clear()
    metrics_cache.clear()
    
    if redis_available:
        try:
            redis_client.flushdb()
        except:
            pass
    
    return {"message": "Cache cleared successfully"}

# Connection pool monitoring
@app.get("/api/performance/connections")
async def get_connection_pool_stats(current_user: User = Depends(require_admin)):
    """Get connection pool statistics."""
    return {
        "available_connections": len(connection_pool.available_connections),
        "in_use_connections": len(connection_pool.in_use_connections),
        "max_connections": connection_pool.max_connections
    }

# Health check endpoints for load balancer
@app.get("/api/health/backend/{backend_url:path}")
async def check_backend_health(
    backend_url: str,
    current_user: User = Depends(get_current_user)
):
    """Check health of a specific backend."""
    is_healthy = await health_checker.check_backend_health(backend_url)
    health_checker.update_health_status(backend_url, is_healthy)
    
    return {
        "backend": backend_url,
        "healthy": is_healthy,
        "checked_at": datetime.utcnow().isoformat()
    }

@app.get("/api/health/backends")
async def get_backend_health_status(current_user: User = Depends(get_current_user)):
    """Get health status of all backends."""
    return {
        "backends": health_checker.health_status,
        "total_backends": len(health_checker.health_status),
        "healthy_backends": len([b for b in health_checker.health_status.values() if b["healthy"]])
    }

# Background task processing
@app.post("/api/tasks/queue")
async def add_background_task(
    task_data: Dict[str, Any],
    current_user: User = Depends(require_admin)
):
    """Add a task to the background queue."""
    task_queue.add_task(
        task_data["function"],
        *task_data.get("args", []),
        **task_data.get("kwargs", {})
    )
    return {"message": "Task added to queue successfully"}

@app.get("/api/tasks/queue/status")
async def get_task_queue_status(current_user: User = Depends(require_admin)):
    """Get task queue status."""
    return {
        "pending_tasks": len(task_queue.tasks),
        "thread_pool_size": thread_pool._max_workers,
        "active_threads": len(thread_pool._threads)
    }

# --- Background Tasks ---
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    logger.info("VPS Manager API starting up...")
    logger.info("Surveyor Indonesia - VPS Manager v2.0.0")



# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# Create structured logger
structured_logger = structlog.get_logger()

# Log retention policy
log_retention_policy = LogRetentionPolicy()

def log_audit_event(
    user_id: str,
    action: str,
    resource: str,
    details: Dict[str, Any] = None,
    ip_address: str = None,
    user_agent: str = None
):
    """Log audit events for compliance and security."""
    audit_log = {
        "event_type": "audit",
        "user_id": user_id,
        "action": action,
        "resource": resource,
        "timestamp": datetime.utcnow().isoformat(),
        "ip_address": ip_address,
        "user_agent": user_agent,
        "details": details or {}
    }
    
    # Log to structured logger
    structured_logger.info(
        "Audit event",
        **audit_log
    )
    
    # Also log to file for compliance
    audit_log_file = LOG_DIR / "audit.log"
    with open(audit_log_file, "a") as f:
        f.write(json.dumps(audit_log) + "\n")

def log_performance_metric(
    operation: str,
    duration_ms: float,
    status_code: int = None,
    details: Dict[str, Any] = None
):
    """Log performance metrics."""
    perf_log = {
        "event_type": "performance",
        "operation": operation,
        "duration_ms": duration_ms,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status_code": status_code,
        "details": details or {}
    }
    
    structured_logger.info(
        "Performance metric",
        **perf_log
    )

def log_security_event(
    event_type: str,
    severity: str,
    message: str,
    ip_address: str = None,
    user_id: str = None,
    details: Dict[str, Any] = None
):
    """Log security events."""
    security_log = {
        "event_type": "security",
        "severity": severity,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_address": ip_address,
        "user_id": user_id,
        "details": details or {}
    }
    
    structured_logger.warning(
        "Security event",
        **security_log
    )

# Custom middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests with performance metrics."""
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Add request ID to request state
    request.state.request_id = request_id
    
    # Log request start
    structured_logger.info(
        "Request started",
        request_id=request_id,
        method=request.method,
        url=str(request.url),
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    try:
        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000
        
        # Log request completion
        structured_logger.info(
            "Request completed",
            request_id=request_id,
            status_code=response.status_code,
            duration_ms=duration_ms
        )
        
        # Log performance metric
        log_performance_metric(
            operation=f"{request.method} {request.url.path}",
            duration_ms=duration_ms,
            status_code=response.status_code
        )
        
        return response
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        
        # Log request error
        structured_logger.error(
            "Request failed",
            request_id=request_id,
            error=str(e),
            duration_ms=duration_ms
        )
        
        raise

# --- Telegram Notification System ---

# Telegram Configuration
TELEGRAM_BOT_TOKEN = "6570760547:AAGJIKY7axGGjGxU5iYmRwU8VKKBk0r1m4g"
TELEGRAM_CHANNEL_ID = "973728242"
TELEGRAM_BOT_USERNAME = "vpnstores_bot"
TELEGRAM_USER_ID = "@horasss"

class TelegramNotifier:
    def __init__(self):
        self.bot_token = TELEGRAM_BOT_TOKEN
        self.channel_id = TELEGRAM_CHANNEL_ID
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
    
    async def send_message(self, message: str, parse_mode: str = "HTML") -> bool:
        """Send message to Telegram channel."""
        try:
            url = f"{self.base_url}/sendMessage"
            data = {
                "chat_id": self.channel_id,
                "text": message,
                "parse_mode": parse_mode
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data) as response:
                    if response.status == 200:
                        logger.info("Telegram notification sent successfully")
                        return True
                    else:
                        logger.error(f"Failed to send Telegram notification: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"Error sending Telegram notification: {e}")
            return False
    
    async def send_alert_notification(self, alert: Alert) -> bool:
        """Send alert notification to Telegram."""
        emoji = "🚨" if alert.status == "active" else "✅"
        message = f"""
{emoji} <b>VPS Manager Alert</b>

<b>Alert:</b> {alert.message}
<b>Metric:</b> {alert.metric}
<b>Value:</b> {alert.value}
<b>Threshold:</b> {alert.threshold}
<b>Status:</b> {alert.status}
<b>Time:</b> {alert.timestamp}

#VPSManager #Alert
        """.strip()
        
        return await self.send_message(message)
    
    async def send_system_notification(self, title: str, message: str, level: str = "info") -> bool:
        """Send system notification to Telegram."""
        emoji_map = {
            "info": "ℹ️",
            "warning": "⚠️",
            "error": "🚨",
            "success": "✅"
        }
        
        emoji = emoji_map.get(level, "ℹ️")
        formatted_message = f"""
{emoji} <b>VPS Manager - {title}</b>

{message}

#VPSManager #System
        """.strip()
        
        return await self.send_message(formatted_message)
    
    async def send_metrics_summary(self, metrics: SystemMetrics) -> bool:
        """Send metrics summary to Telegram."""
        message = f"""
📊 <b>VPS Manager - System Metrics</b>

<b>CPU Usage:</b> {metrics.cpu_usage:.1f}%
<b>Memory Usage:</b> {metrics.memory_usage:.1f}%
<b>Disk Usage:</b> {metrics.disk_usage:.1f}%
<b>Network In:</b> {metrics.network_in:.2f} MB
<b>Network Out:</b> {metrics.network_out:.2f} MB
<b>Nginx Connections:</b> {metrics.nginx_connections}
<b>Requests/sec:</b> {metrics.nginx_requests_per_second:.2f}

#VPSManager #Metrics
        """.strip()
        
        return await self.send_message(message)
    
    async def send_backup_notification(self, action: str, details: str) -> bool:
        """Send backup notification to Telegram."""
        emoji = "💾" if "create" in action else "🔄" if "restore" in action else "🗑️"
        message = f"""
{emoji} <b>VPS Manager - Backup {action.title()}</b>

{details}

#VPSManager #Backup
        """.strip()
        
        return await self.send_message(message)
    
    async def send_ssl_notification(self, action: str, domain: str, details: str) -> bool:
        """Send SSL certificate notification to Telegram."""
        emoji = "🔒" if "renew" in action else "📝" if "request" in action else "⚠️"
        message = f"""
{emoji} <b>VPS Manager - SSL Certificate {action.title()}</b>

<b>Domain:</b> {domain}
<b>Details:</b> {details}

#VPSManager #SSL
        """.strip()
        
        return await self.send_message(message)
    
    async def send_config_notification(self, action: str, config_id: str, details: str) -> bool:
        """Send configuration change notification to Telegram."""
        emoji = "⚙️" if "create" in action else "✏️" if "update" in action else "🗑️"
        message = f"""
{emoji} <b>VPS Manager - Configuration {action.title()}</b>

<b>Config ID:</b> {config_id}
<b>Details:</b> {details}

#VPSManager #Config
        """.strip()
        
        return await self.send_message(message)

# Global Telegram notifier
telegram_notifier = TelegramNotifier()

# Enhanced alert checking with Telegram notifications
def check_alerts_with_notification(metrics: SystemMetrics):
    """Check alert rules against current metrics and send Telegram notifications."""
    for rule in alert_rules:
        if not rule.enabled:
            continue
            
        value = getattr(metrics, rule.metric, 0.0)
        triggered = False
        
        if rule.operator == ">":
            triggered = value > rule.threshold
        elif rule.operator == "<":
            triggered = value < rule.threshold
        elif rule.operator == ">=":
            triggered = value >= rule.threshold
        elif rule.operator == "<=":
            triggered = value <= rule.threshold
        elif rule.operator == "==":
            triggered = value == rule.threshold
            
        if triggered:
            # Check if alert already exists
            existing_alert = next((a for a in active_alerts if a.rule_id == rule.id and a.status == "active"), None)
            if not existing_alert:
                alert = Alert(
                    id=f"alert_{int(time.time())}",
                    rule_id=rule.id,
                    timestamp=datetime.utcnow().isoformat(),
                    metric=rule.metric,
                    value=value,
                    threshold=rule.threshold,
                    status="active",
                    message=f"{rule.metric} is {rule.operator} {rule.threshold} (current: {value})"
                )
                active_alerts.append(alert)
                logger.warning(f"Alert triggered: {alert.message}")
                
                # Send Telegram notification
                asyncio.create_task(telegram_notifier.send_alert_notification(alert))