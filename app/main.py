import os
import json
import subprocess
import logging
import re
import shlex
from typing import List, Optional, Dict
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ValidationError, Field, field_validator
from datetime import datetime
from pathlib import Path
import contextlib

# --- Configuration ---
BASE_DIR = Path("/opt/vps-manager")
NGINX_DIR = Path("/etc/nginx")
NGINX_SITES_AVAILABLE = NGINX_DIR / "sites-available"
NGINX_SITES_ENABLED = NGINX_DIR / "sites-enabled"
CONFIG_DB = BASE_DIR / "app" / "config_db.json"
LOG_DIR = BASE_DIR / "logs"

# SSL Wildcard for all .ptsi.co.id domains
DEFAULT_SSL_CERT = Path("/etc/ssl/ptsi/wildcard.ptsi.co.id.crt")
DEFAULT_SSL_KEY = Path("/etc/ssl/ptsi/wildcard.ptsi.co.id.key")

# --- Setup Logging ---
LOG_FILE_APP = LOG_DIR / "vps-manager.log"
LOG_FILE_NGINX_ACCESS_PREFIX = LOG_DIR
LOG_FILE_NGINX_ERROR_PREFIX = LOG_DIR

# Ensure log directory exists
LOG_DIR.mkdir(parents=True, exist_ok=True)

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
    title="VPS Manager API",
    docs_url="/docs",
    redoc_url=None
)

# --- Ensure Directories Exist ---
NGINX_SITES_AVAILABLE.mkdir(parents=True, exist_ok=True)
NGINX_SITES_ENABLED.mkdir(parents=True, exist_ok=True)

# --- Custom Exceptions ---
class CommandExecutionError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)

class ConfigNotFoundError(HTTPException):
    def __init__(self, config_id: str):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=f"Config with ID '{config_id}' not found")

class ConfigAlreadyExistsError(HTTPException):
    def __init__(self, config_id: str):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=f"Config with ID '{config_id}' already exists")

class InvalidSSLCertificateError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

class InvalidConfigIdError(HTTPException):
    def __init__(self, config_id: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid config ID '{config_id}'. Only alphanumeric, hyphens, and underscores are allowed."
        )

# --- Pydantic Models ---
class ProxyLocation(BaseModel):
    path: str = Field(..., pattern=r"^/[a-zA-Z0-9_\-/]*$")
    backend: str  # Format: "ip:port" or "https://ip:port"
    proxy_http_version: Optional[str] = Field(None, pattern=r"^1\.(0|1)$")
    websocket: bool = False
    ssl_verify: bool = True
    custom_headers: Optional[Dict[str, str]] = {}

    @field_validator("backend")
    def validate_backend(cls, v):
        # Validate IPv4, IPv6, or domain format
        if v.startswith(('http://', 'https://')):
            backend = v.split('://')[1]
        else:
            backend = v
            
        parts = backend.rsplit(':', 1)
        if len(parts) != 2:
            raise ValueError("Backend must be in format 'host:port' or 'scheme://host:port'")
            
        host, port = parts
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValueError("Port must be between 1 and 65535")
        except ValueError:
            raise ValueError("Port must be a valid integer")
            
        return v

class ServerConfig(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9_\-]+$")
    server_name: str
    listen_port: int = Field(80, ge=1, le=65535)
    ssl_cert: Optional[Path] = None
    ssl_key: Optional[Path] = None
    locations: List[ProxyLocation] = Field(..., min_length=1)
    is_active: bool = True
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

# --- Utility Functions ---
def run_command(cmd: List[str]) -> str:
    """Executes a shell command and returns its stdout, raises CommandExecutionError on failure."""
    safe_cmd = ' '.join(shlex.quote(arg) for arg in cmd)
    logger.info(f"Executing command: {safe_cmd}")
    try:
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )
        logger.info(f"Command successful: {result.stdout.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed: '{safe_cmd}' - Exit code: {e.returncode} - Stderr: {e.stderr.strip()}"
        logger.error(error_msg)
        raise CommandExecutionError(detail=error_msg)
    except FileNotFoundError:
        error_msg = f"Command not found: '{cmd[0]}'. Make sure it's in the system's PATH."
        logger.error(error_msg)
        raise CommandExecutionError(detail=error_msg)
    except Exception as e:
        error_msg = f"Unexpected error running command '{safe_cmd}': {str(e)}"
        logger.error(error_msg)
        raise CommandExecutionError(detail=error_msg)

def load_configs() -> List[ServerConfig]:
    """Loads server configurations from the JSON database file."""
    if not CONFIG_DB.exists():
        logger.info(f"Config database not found at {CONFIG_DB}. Returning empty list.")
        return []
    try:
        with open(CONFIG_DB, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        configs = []
        for item in data:
            try:
                configs.append(ServerConfig(**item))
            except ValidationError as e:
                logger.warning(f"Skipping invalid config entry: {json.dumps(item)} - Errors: {e.errors()}")
        return configs
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {CONFIG_DB}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration database is corrupted"
        )
    except Exception as e:
        logger.error(f"Unexpected error loading configurations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load configurations"
        )

def save_configs(configs: List[ServerConfig]):
    """Saves server configurations to the JSON database file."""
    try:
        CONFIG_DB.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_DB, 'w', encoding='utf-8') as f:
            json.dump(
                [config.model_dump(mode='json') for config in configs],
                f,
                indent=2,
                ensure_ascii=False
            )
        logger.info(f"Configurations saved to {CONFIG_DB}")
    except Exception as e:
        logger.error(f"Failed to save configurations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save configurations"
        )

def generate_location_block(location: ProxyLocation) -> str:
    """Generates an Nginx location block configuration string."""
    # Sanitize path to prevent injection
    sanitized_path = location.path.replace('"', '\\"').replace(';', '')
    
    block = f"\n    location {sanitized_path} {{\n"
    
    # Determine proxy target
    if location.backend.startswith(('http://', 'https://')):
        proxy_pass_target = location.backend
    else:
        proxy_pass_target = f"http://{location.backend}"

    block += f"        proxy_pass {proxy_pass_target};\n"
    
    # Standard headers
    headers = [
        "Host $host",
        "X-Real-IP $remote_addr",
        "X-Forwarded-For $proxy_add_x_forwarded_for",
        "X-Forwarded-Proto $scheme"
    ]
    
    # Websocket support
    if location.websocket:
        headers.append("Upgrade $http_upgrade")
        headers.append('Connection "upgrade"')
        block += "        proxy_http_version 1.1;\n"
    
    # Custom HTTP version
    if location.proxy_http_version:
        block += f"        proxy_http_version {location.proxy_http_version};\n"
    
    # SSL verification
    if proxy_pass_target.startswith('https://') and not location.ssl_verify:
        block += "        proxy_ssl_verify off;\n"
        logger.warning(f"SSL verification disabled for backend: {proxy_pass_target}")
    
    # Add headers
    for header in headers:
        block += f"        proxy_set_header {header};\n"
    
    # Custom headers
    for header, value in location.custom_headers.items():
        sanitized_value = value.replace('"', '\\"').replace('\n', '')
        block += f'        proxy_set_header {header} "{sanitized_value}";\n'
    
    block += "    }\n"
    return block

def generate_nginx_config_content(config: ServerConfig) -> str:
    """Generates the full Nginx server block configuration with improved settings."""
    # Sanitize server name
    server_name = re.sub(r'[;\{\}]', '', config.server_name)
    
    ssl_directives = ""
    listen_directive = f"listen {config.listen_port} http2"
    
    # Determine SSL usage
    use_default_ssl = config.server_name.endswith('.ptsi.co.id') and not config.ssl_cert and not config.ssl_key
    
    if use_default_ssl or (config.ssl_cert and config.ssl_key):
        listen_directive += " ssl"
        ssl_cert_path = DEFAULT_SSL_CERT if use_default_ssl else config.ssl_cert
        ssl_key_path = DEFAULT_SSL_KEY if use_default_ssl else config.ssl_key

        # Validate SSL files
        if not ssl_cert_path.exists() or not ssl_key_path.exists():
            missing = []
            if not ssl_cert_path.exists():
                missing.append(f"Certificate: {ssl_cert_path}")
            if not ssl_key_path.exists():
                missing.append(f"Key: {ssl_key_path}")
            raise InvalidSSLCertificateError(f"SSL files missing: {', '.join(missing)}")
        
        ssl_directives = f"""
        ssl_certificate {ssl_cert_path};
        ssl_certificate_key {ssl_key_path};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        """

    location_blocks = "".join(generate_location_block(loc) for loc in config.locations)

    # Security headers
    security_headers = """
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Content-Type-Options "nosniff";
        add_header Referrer-Policy "strict-origin-when-cross-origin";
    """

    # Gzip compression
    gzip_config = """
        gzip on;
        gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
        gzip_min_length 1000;
        gzip_proxied any;
    """

    # Static file caching
    static_file_caching = """
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 30d;
            add_header Cache-Control "public, max-age=2592000";
        }
    """

    # Include shared configurations
    include_directives = """
        include /etc/nginx/conf.d/*.conf;
    """

    return f"""
server {{
    {listen_directive};
    server_name {server_name};

    {ssl_directives}

    access_log {LOG_FILE_NGINX_ACCESS_PREFIX / f'{config.id}_access.log'} main;
    error_log {LOG_FILE_NGINX_ERROR_PREFIX / f'{config.id}_error.log'} warn;

    {security_headers}
    {gzip_config}
    {static_file_caching}
    {include_directives}

    {location_blocks}
}}
"""

def apply_nginx_config(config: ServerConfig):
    """Writes config to file, manages symlinks, and reloads Nginx."""
    config_file = NGINX_SITES_AVAILABLE / f"{config.id}.conf"
    enabled_link = NGINX_SITES_ENABLED / config_file.name

    try:
        config_content = generate_nginx_config_content(config)
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(config_content)
        logger.info(f"Config written: {config_file}")
    except Exception as e:
        logger.error(f"Config generation failed for {config.id}: {str(e)}")
        raise

    # Manage symlink
    if config.is_active:
        if enabled_link.exists():
            if enabled_link.is_symlink():
                enabled_link.unlink()
            else:
                logger.warning(f"Removing non-symlink file: {enabled_link}")
                enabled_link.unlink()
        enabled_link.symlink_to(config_file)
        logger.info(f"Enabled config: {enabled_link}")
    elif enabled_link.exists():
        enabled_link.unlink()
        logger.info(f"Disabled config: {enabled_link}")

    # Reload Nginx safely
    try:
        run_command(["nginx", "-t"])
        run_command(["systemctl", "reload", "nginx"])
        logger.info("Nginx reloaded successfully")
    except CommandExecutionError:
        logger.error("Nginx reload failed! Configuration may be in inconsistent state")
        raise

# --- API Endpoints ---
@app.post("/configs/", response_model=ServerConfig, status_code=status.HTTP_201_CREATED)
def create_config(config: ServerConfig):
    """Creates a new Nginx server configuration."""
    configs = load_configs()
    
    # ID validation
    if not re.match(r"^[a-zA-Z0-9_\-]+$", config.id):
        raise InvalidConfigIdError(config.id)
    
    if any(c.id == config.id for c in configs):
        raise ConfigAlreadyExistsError(config.id)

    # SSL validation
    if (config.ssl_cert and not config.ssl_key) or (not config.ssl_cert and config.ssl_key):
        raise InvalidSSLCertificateError("Both SSL cert and key must be provided or omitted")
    
    if config.ssl_cert and not config.ssl_cert.exists():
        raise InvalidSSLCertificateError(f"SSL certificate not found: {config.ssl_cert}")
    if config.ssl_key and not config.ssl_key.exists():
        raise InvalidSSLCertificateError(f"SSL key not found: {config.ssl_key}")

    # Default SSL validation
    if config.server_name.endswith('.ptsi.co.id') and not config.ssl_cert:
        if not DEFAULT_SSL_CERT.exists() or not DEFAULT_SSL_KEY.exists():
            missing = []
            if not DEFAULT_SSL_CERT.exists():
                missing.append("default cert")
            if not DEFAULT_SSL_KEY.exists():
                missing.append("default key")
            raise InvalidSSLCertificateError(f"Default SSL files missing: {', '.join(missing)}")

    configs.append(config)
    save_configs(configs)
    apply_nginx_config(config)
    logger.info(f"Config created: {config.id}")
    return config

@app.get("/configs/", response_model=List[ServerConfig])
def read_all_configs():
    """Retrieves all configurations."""
    return load_configs()

@app.get("/configs/{config_id}", response_model=ServerConfig)
def read_single_config(config_id: str):
    """Retrieves a specific configuration."""
    configs = load_configs()
    for config in configs:
        if config.id == config_id:
            return config
    raise ConfigNotFoundError(config_id)

@app.put("/configs/{config_id}", response_model=ServerConfig)
def update_config(config_id: str, updated_config: ServerConfig):
    """Updates an existing configuration."""
    if config_id != updated_config.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Config ID in path doesn't match request body"
        )
    
    configs = load_configs()
    for i, config in enumerate(configs):
        if config.id == config_id:
            # SSL validation
            if (updated_config.ssl_cert and not updated_config.ssl_key) or (not updated_config.ssl_cert and updated_config.ssl_key):
                raise InvalidSSLCertificateError("Both SSL cert and key must be provided or omitted")
            
            if updated_config.ssl_cert and not updated_config.ssl_cert.exists():
                raise InvalidSSLCertificateError(f"SSL certificate not found: {updated_config.ssl_cert}")
            if updated_config.ssl_key and not updated_config.ssl_key.exists():
                raise InvalidSSLCertificateError(f"SSL key not found: {updated_config.ssl_key}")

            # Default SSL validation
            if updated_config.server_name.endswith('.ptsi.co.id') and not updated_config.ssl_cert:
                if not DEFAULT_SSL_CERT.exists() or not DEFAULT_SSL_KEY.exists():
                    missing = []
                    if not DEFAULT_SSL_CERT.exists():
                        missing.append("default cert")
                    if not DEFAULT_SSL_KEY.exists():
                        missing.append("default key")
                    raise InvalidSSLCertificateError(f"Default SSL files missing: {', '.join(missing)}")

            updated_config.updated_at = datetime.utcnow().isoformat()
            configs[i] = updated_config
            save_configs(configs)
            apply_nginx_config(updated_config)
            logger.info(f"Config updated: {config_id}")
            return updated_config
    
    raise ConfigNotFoundError(config_id)

@app.delete("/configs/{config_id}", status_code=status.HTTP_200_OK)
def delete_config(config_id: str):
    """Deletes a configuration."""
    configs = load_configs()
    original_count = len(configs)
    
    # Filter and remove
    configs = [c for c in configs if c.id != config_id]
    
    if len(configs) == original_count:
        raise ConfigNotFoundError(config_id)
    
    save_configs(configs)
    
    # Remove files
    config_file = NGINX_SITES_AVAILABLE / f"{config_id}.conf"
    enabled_link = NGINX_SITES_ENABLED / f"{config_id}.conf"
    
    # Remove files with error suppression
    with contextlib.suppress(FileNotFoundError):
        if enabled_link.exists():
            enabled_link.unlink()
            logger.info(f"Removed symlink: {enabled_link}")
    
    with contextlib.suppress(FileNotFoundError):
        if config_file.exists():
            config_file.unlink()
            logger.info(f"Removed config: {config_file}")
    
    # Reload Nginx if needed
    try:
        run_command(["nginx", "-t"])
        run_command(["systemctl", "reload", "nginx"])
        logger.info("Nginx reloaded after deletion")
    except CommandExecutionError as e:
        logger.error(f"Nginx reload failed after deletion: {e.detail}")
    
    logger.info(f"Config deleted: {config_id}")
    return {"message": f"Config '{config_id}' deleted"}

@app.post("/configs/{config_id}/toggle", response_model=ServerConfig)
def toggle_config_status(config_id: str):
    """Toggles configuration active status."""
    configs = load_configs()
    for i, config in enumerate(configs):
        if config.id == config_id:
            config.is_active = not config.is_active
            config.updated_at = datetime.utcnow().isoformat()
            save_configs(configs)
            apply_nginx_config(config)
            status = "enabled" if config.is_active else "disabled"
            logger.info(f"Config {status}: {config_id}")
            return config
    raise ConfigNotFoundError(config_id)

# --- Main Execution ---
if __name__ == "__main__":
    import uvicorn
    
    # Security check
    if os.geteuid() != 0:
        logger.critical("Must be run as root")
        exit(1)
    
    # Start server
    logger.info("Starting VPS Manager API")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_config=None,
        timeout_keep_alive=30
    )