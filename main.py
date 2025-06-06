import os
import json
import subprocess
import logging
import re
import shlex
import psutil
import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, status, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ValidationError, Field, field_validator
from datetime import datetime, timedelta
from pathlib import Path
import contextlib
import asyncio
import aiofiles
from collections import defaultdict

# Import authentication
from auth import (
    User, LoginRequest, TokenResponse, authenticate_user, 
    get_current_user, require_admin, create_access_token
)

# --- Configuration ---
BASE_DIR = Path("/opt/vps-manager")
NGINX_DIR = Path("/etc/nginx")
NGINX_SITES_AVAILABLE = NGINX_DIR / "sites-available"
NGINX_SITES_ENABLED = NGINX_DIR / "sites-enabled"
CONFIG_DB = BASE_DIR / "app" / "config_db.json"
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
    server_name: str
    listen_port: int = Field(80, ge=1, le=65535)
    locations: List[ProxyLocation] = Field(..., min_length=1)
    upstream: Optional[LoadBalancerUpstream] = None
    is_active: bool = True
    rate_limit_global: Optional[str] = None
    access_log_enabled: bool = True
    error_log_enabled: bool = True
    gzip_enabled: bool = True
    security_headers: bool = True
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: Optional[str] = None

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

# --- Authentication Endpoints ---
@app.post("/api/auth/login", response_model=TokenResponse)
async def login(login_data: LoginRequest):
    """Authenticate user and return JWT token"""
    user = authenticate_user(login_data.username, login_data.password)
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
    server_name = re.sub(r'[;\{\}]', '', config.server_name)
    
    upstream_block = ""
    upstream_name = None
    if config.upstream:
        upstream_name = config.upstream.name
        upstream_block = generate_upstream_block(config.upstream)
    
    listen_directive = f"listen {config.listen_port} ssl http2"
    
    ssl_directives = f"""
        ssl_certificate {DEFAULT_SSL_CERT};
        ssl_certificate_key {DEFAULT_SSL_KEY};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;
        ssl_stapling on;
        ssl_stapling_verify on;
        """

    rate_limit_directives = ""
    if config.rate_limit_global:
        rate_limit_directives = f"""
        limit_req_zone $binary_remote_addr zone=global:{config.rate_limit_global};
        limit_req zone=global burst=20 nodelay;
        """

    location_blocks = "".join(generate_location_block(loc, upstream_name) for loc in config.locations)

    security_headers = ""
    if config.security_headers:
        security_headers = """
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;
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
    server_name {server_name};

    {ssl_directives}
    {rate_limit_directives}

    {access_log}
    {error_log}

    {security_headers}
    {gzip_config}

    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2|ttf|eot)$ {{
        expires 30d;
        add_header Cache-Control "public, max-age=2592000";
        add_header Vary Accept-Encoding;
    }}

    location ~ /\. {{
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

@app.post("/api/configs", response_model=ServerConfig, status_code=201)
async def create_config(config: ServerConfig, current_user: User = Depends(get_current_user)):
    """Creates a new Nginx server configuration."""
    configs = await load_configs()
    
    if any(c.id == config.id for c in configs):
        raise HTTPException(status_code=409, detail=f"Config with ID '{config.id}' already exists")

    config.created_by = current_user.username
    
    configs.append(config)
    await save_configs(configs)
    await apply_nginx_config(config)
    logger.info(f"Config created by {current_user.username}: {config.id}")
    return config

@app.put("/api/configs/{config_id}", response_model=ServerConfig)
async def update_config(config_id: str, updated_config: ServerConfig, current_user: User = Depends(get_current_user)):
    """Updates an existing configuration."""
    if config_id != updated_config.id:
        raise HTTPException(status_code=400, detail="Config ID in path doesn't match request body")
    
    configs = await load_configs()
    for i, config in enumerate(configs):
        if config.id == config_id:
            if current_user.role != "admin" and config.created_by != current_user.username:
                raise HTTPException(status_code=403, detail="You can only edit your own configurations")
            
            updated_config.updated_at = datetime.utcnow().isoformat()
            configs[i] = updated_config
            await save_configs(configs)
            await apply_nginx_config(updated_config)
            logger.info(f"Config updated by {current_user.username}: {config_id}")
            return updated_config
    
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

# --- Background Tasks ---
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    logger.info("VPS Manager API starting up...")
    logger.info("Surveyor Indonesia - VPS Manager v2.0.0")

if __name__ == "__main__":
    import uvicorn
    
    if os.geteuid() != 0:
        logger.critical("Must be run as root")
        exit(1)
    
    logger.info("Starting VPS Manager API v2.0.0 - Surveyor Indonesia")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_config=None,
        timeout_keep_alive=30,
        access_log=True
    )