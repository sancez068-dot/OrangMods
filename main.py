import os
import sys
import hashlib
import secrets
import logging
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, Response
from pydantic import BaseModel, Field, validator
from jose import jwt, JWTError, ExpiredSignatureError
from datetime import timezone
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from cachetools import TTLCache
import asyncpg
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import asyncio

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logger.error("SECRET_KEY environment variable is required!")
    sys.exit(1)

DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME")
DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD")
if not DEFAULT_ADMIN_USERNAME or not DEFAULT_ADMIN_PASSWORD:
    logger.error("DEFAULT_ADMIN_USERNAME and DEFAULT_ADMIN_PASSWORD are required!")
    sys.exit(1)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    logger.error("DATABASE_URL environment variable is required!")
    sys.exit(1)

# Поддержка SQLite и PostgreSQL
if DATABASE_URL.startswith("postgresql"):
    IS_POSTGRES = True
    # Конвертируем postgresql:// в postgresql+asyncpg://
    ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
else:
    IS_POSTGRES = False
    ASYNC_DATABASE_URL = DATABASE_URL

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")
MAX_LIMIT = int(os.getenv("MAX_LIMIT", "100"))

# ============================================================
# КЕШ ДЛЯ /API/INFOKEY
# ============================================================

INFO_CACHE = TTLCache(maxsize=50000, ttl=30)
CACHE_HITS = 0
CACHE_MISSES = 0

# ============================================================
# SQLALCHEMY SETUP
# ============================================================

engine = create_async_engine(ASYNC_DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# ============================================================
# МОДЕЛИ ДАННЫХ
# ============================================================

class AdminLogin(BaseModel):
    login: str
    password: str

class KeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    type: str = Field(..., pattern="^(DAY|HOUR)$")
    duration: int = Field(..., gt=0, le=365)
    max_devices: int = Field(..., ge=1, le=999)
    max_percent: int = Field(..., ge=40, le=95)
    
    @validator('max_percent')
    def validate_percent(cls, v):
        if v < 40 or v > 95:
            raise ValueError('max_percent must be between 40 and 95')
        return v

class ActivationRequest(BaseModel):
    key_code: str = Field(..., min_length=1, max_length=100)
    device_id: str = Field(..., min_length=1, max_length=255)

class CheckUpdateRequest(BaseModel):
    current_version: str = Field(..., min_length=1, max_length=20)
    platform: str = Field(..., pattern="^(android|ios|windows)$")

class NotificationCreate(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000)

class AdCreate(BaseModel):
    html: str
    is_closable: bool = True

class DeviceRegister(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=255)
    platform: str = Field(..., pattern="^(android|ios|web|windows)$")
    push_token: Optional[str] = Field(None, max_length=500)

class DeviceNotification(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=255)
    title: str = Field(..., min_length=1, max_length=100)
    body: str = Field(..., min_length=1, max_length=500)
    data: Optional[Dict[str, str]] = None

class BroadcastNotification(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    body: str = Field(..., min_length=1, max_length=500)
    platform: Optional[str] = Field(None, pattern="^(android|ios|web|windows)$")
    data: Optional[Dict[str, str]] = None

class SettingsUpdate(BaseModel):
    telegram_username: Optional[str] = Field(None, max_length=100)
    app_name: Optional[str] = Field(None, max_length=100)
    support_email: Optional[str] = Field(None, max_length=100)

# ============================================================
# WEBSOCKET MANAGER
# ============================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.admin_connections: Dict[int, WebSocket] = {}

    async def connect_device(self, device_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[device_id] = websocket
        logger.info(f"Device connected: {device_id}")

    def disconnect_device(self, device_id: str):
        if device_id in self.active_connections:
            del self.active_connections[device_id]
            logger.info(f"Device disconnected: {device_id}")

    async def connect_admin(self, admin_id: int, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections[admin_id] = websocket
        logger.info(f"Admin connected: {admin_id}")

    def disconnect_admin(self, admin_id: int):
        if admin_id in self.admin_connections:
            del self.admin_connections[admin_id]
            logger.info(f"Admin disconnected: {admin_id}")

    async def send_to_device(self, device_id: str, message: dict):
        if device_id in self.active_connections:
            try:
                await self.active_connections[device_id].send_json(message)
                return True
            except:
                self.disconnect_device(device_id)
        return False

    async def send_to_admin(self, admin_id: int, message: dict):
        if admin_id in self.admin_connections:
            try:
                await self.admin_connections[admin_id].send_json(message)
                return True
            except:
                self.disconnect_admin(admin_id)
        return False

    async def broadcast_to_devices(self, message: dict, platform: str = None):
        sent = 0
        for device_id, websocket in list(self.active_connections.items()):
            try:
                if platform:
                    async with get_db() as conn:
                        row = await conn.fetchrow(
                            "SELECT platform FROM devices WHERE device_id = $1 AND is_active = true",
                            device_id
                        )
                        if not row or row['platform'] != platform:
                            continue
                
                await websocket.send_json(message)
                sent += 1
            except:
                self.disconnect_device(device_id)
        return sent

manager = ConnectionManager()

# ============================================================
# DATABASE FUNCTIONS
# ============================================================

async def get_db_conn():
    """Получить подключение к БД"""
    return await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))

async def init_database():
    """Инициализация таблиц"""
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        # Таблица администраторов
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Таблица ключей
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id SERIAL PRIMARY KEY,
                key_value TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('DAY', 'HOUR')),
                duration INTEGER NOT NULL,
                max_devices INTEGER NOT NULL,
                max_percent INTEGER NOT NULL,
                used_devices INTEGER DEFAULT 0,
                first_activation TIMESTAMP,
                status TEXT DEFAULT 'waiting',
                is_active BOOLEAN DEFAULT TRUE,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES admins(id)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys(key_value)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)")
        
        # Таблица активаций
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS activations (
                id SERIAL PRIMARY KEY,
                key_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (key_id) REFERENCES keys(id),
                UNIQUE(key_id, device_id)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_activations_key_id ON activations(key_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_activations_device_id ON activations(device_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_activations_expires_at ON activations(expires_at)")
        
        # Таблица уведомлений
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)")
        
        # Таблица рекламы
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS advertisements (
                id SERIAL PRIMARY KEY,
                html TEXT NOT NULL,
                is_closable BOOLEAN DEFAULT TRUE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Таблица логов
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                admin_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at)")
        
        # Таблица обновлений
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS updates (
                id SERIAL PRIMARY KEY,
                version TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL CHECK(platform IN ('android', 'ios', 'windows')),
                download_url TEXT NOT NULL,
                changelog TEXT,
                is_forced BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_updates_platform ON updates(platform)")
        
        # Таблица устройств
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id SERIAL PRIMARY KEY,
                device_id TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL CHECK(platform IN ('android', 'ios', 'web', 'windows')),
                push_token TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_push_token ON devices(push_token)")
        
        # Таблица уведомлений для устройств
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS device_notifications (
                id SERIAL PRIMARY KEY,
                device_id TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                data TEXT,
                is_read BOOLEAN DEFAULT FALSE,
                is_delivered BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_device_notifications_device ON device_notifications(device_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_device_notifications_read ON device_notifications(is_read)")
        
        # Таблица настроек
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id SERIAL PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key)")
        
        # Создание админа
        row = await conn.fetchrow("SELECT COUNT(*) FROM admins")
        if row and row[0] == 0:
            hashed = get_password_hash(DEFAULT_ADMIN_PASSWORD)
            await conn.execute(
                "INSERT INTO admins (username, password_hash) VALUES ($1, $2)",
                DEFAULT_ADMIN_USERNAME, hashed
            )
            logger.info(f"Created default admin user: {DEFAULT_ADMIN_USERNAME}")
        
        # Получаем ID админа
        row = await conn.fetchrow("SELECT id FROM admins WHERE username = $1", DEFAULT_ADMIN_USERNAME)
        admin_id = row['id'] if row else 1
        
        # Добавляем дефолтные настройки
        await conn.execute("""
            INSERT INTO settings (key, value) VALUES 
            ('telegram_username', 'SofterTeamBot'),
            ('app_name', 'OrangMods'),
            ('support_email', 'support@orangmods.com')
            ON CONFLICT (key) DO NOTHING
        """)
        
        # Создание тестовых ключей
        row = await conn.fetchrow("SELECT COUNT(*) FROM keys")
        if row and row[0] == 0:
            test_keys = [
                ("OrangMods-7DAY-XYZ123", "Тестовый ключ 1", "DAY", 7, 5, 70, "active"),
                ("OrangMods-30DAY-ABC456", "Тестовый ключ 2", "DAY", 30, 10, 80, "waiting"),
                ("OrangMods-12HOUR-DEF789", "Тестовый ключ 3", "HOUR", 12, 3, 90, "expired"),
                ("OrangMods-1DAY-6XGXQRDJ5Y", "Тестовый ключ 4", "DAY", 1, 3, 80, "waiting"),
            ]
            for key in test_keys:
                await conn.execute("""
                    INSERT INTO keys (key_value, name, type, duration, max_devices, max_percent, status, created_by)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """, *key, admin_id)
            logger.info("Created test keys")
        
        # Создание тестовой рекламы
        row = await conn.fetchrow("SELECT COUNT(*) FROM advertisements")
        if row and row[0] == 0:
            await conn.execute("""
                INSERT INTO advertisements (html, is_closable, is_active)
                VALUES ($1, $2, $3)
            """, '<div style="padding:20px;background:linear-gradient(135deg,#ff7300,#ffb300);border-radius:12px;color:#fff;text-align:center;font-size:18px;">🍊 OrangMods - Ваш лучший выбор!</div>', True, True)
            logger.info("Created test advertisement")
            
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database init error: {e}")
        raise
    finally:
        await conn.close()

# ============================================================
# БЕЗОПАСНОСТЬ
# ============================================================

security = HTTPBearer()

def get_password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    return f"{salt}:{hashlib.sha256((salt + password).encode()).hexdigest()}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, hash_value = hashed.split(":")
        return hash_value == hashlib.sha256((salt + password).encode()).hexdigest()
    except ValueError:
        return False

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,
        "iat": now,
        "iss": "orangmods-api"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("iss") != "orangmods-api":
            raise HTTPException(status_code=401, detail="Invalid token issuer")
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    admin_id = payload.get("sub")
    if not admin_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow(
            "SELECT id, username FROM admins WHERE id = $1 AND is_active = true",
            int(admin_id)
        )
        if not row:
            raise HTTPException(status_code=401, detail="Admin not found")
        return {"id": row['id'], "username": row['username']}
    finally:
        await conn.close()

# ============================================================
# LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Инициализация БД
    await init_database()
    
    # Планировщик
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        cleanup_expired_activations,
        trigger=IntervalTrigger(minutes=30),
        id="cleanup_expired_activations"
    )
    scheduler.start()
    logger.info("Application started successfully")
    yield
    scheduler.shutdown()
    logger.info("Application shutting down")

app = FastAPI(
    title="OrangMods API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan
)

# ============================================================
# MIDDLEWARE
# ============================================================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        logger.error(f"Error processing {request.url.path}: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )

# ============================================================
# CORS
# ============================================================

if "*" in ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

if ALLOWED_HOSTS != ["*"]:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=ALLOWED_HOSTS
    )

# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

def generate_key_code(key_type: str, duration: int) -> str:
    type_map = {"DAY": f"{duration}DAY", "HOUR": f"{duration}HOUR"}
    type_str = type_map.get(key_type, "DAY")
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    random_part = ''.join(secrets.choice(chars) for _ in range(10))
    return f"OrangMods-{type_str}-{random_part}"

async def log_action(admin_id: int, action: str, details: str = None, ip: str = None):
    try:
        conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
        try:
            await conn.execute(
                "INSERT INTO logs (admin_id, action, details, ip_address) VALUES ($1, $2, $3, $4)",
                admin_id, action, details, ip
            )
        finally:
            await conn.close()
    except Exception as e:
        logger.error(f"Error logging action: {e}")

def calculate_time_left(key: dict) -> dict:
    if key.get('status') != 'active' or not key.get('first_activation'):
        return {'time_left': 'НЕТ', 'time_left_seconds': 0}
    
    try:
        first_act = key['first_activation']
        if isinstance(first_act, str):
            first_act = datetime.fromisoformat(first_act.replace(' ', 'T'))
        
        now = datetime.now()
        delta = now - first_act
        
        if key.get('type') == 'DAY':
            total_seconds = key.get('duration', 0) * 24 * 3600
        else:
            total_seconds = key.get('duration', 0) * 3600
        
        elapsed = delta.total_seconds()
        left = max(0, total_seconds - elapsed)
        
        hours = int(left // 3600)
        minutes = int((left % 3600) // 60)
        
        return {
            'time_left': f"{hours}ч {minutes}м",
            'time_left_seconds': left
        }
    except Exception as e:
        logger.error(f"Error calculating time left: {e}")
        return {'time_left': 'Ошибка', 'time_left_seconds': 0}

async def format_key_row(row) -> dict:
    key_dict = {
        "id": row['id'],
        "key_value": row['key_value'],
        "name": row['name'],
        "type": row['type'],
        "duration": row['duration'],
        "max_devices": row['max_devices'],
        "max_percent": row['max_percent'],
        "used_devices": row['used_devices'],
        "first_activation": row['first_activation'],
        "status": row['status'],
        "created_at": row['created_at']
    }
    time_info = calculate_time_left(key_dict)
    key_dict.update(time_info)
    return key_dict

async def cleanup_expired_activations():
    try:
        conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
        try:
            # Обновляем статусы ключей
            result = await conn.execute("""
                UPDATE keys 
                SET status = 'expired' 
                WHERE status = 'active' 
                AND first_activation + (duration || ' ' || 
                    CASE WHEN type = 'DAY' THEN 'days' ELSE 'hours' END)::INTERVAL < NOW()
            """)
            logger.info(f"Cleaned up expired keys")
            
            # Деактивируем просроченные активации
            result = await conn.execute("""
                UPDATE activations 
                SET is_active = false 
                WHERE is_active = true AND expires_at < NOW()
            """)
        finally:
            await conn.close()
    except Exception as e:
        logger.error(f"Error cleaning up: {e}")

# ============================================================
# HTML АДМИНКА
# ============================================================

STATIC_DIR = Path("static")
STATIC_DIR.mkdir(exist_ok=True)

ADMIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OrangMods Admin Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Orbitron', sans-serif;
        }

        body {
            min-height: 100vh;
            background: radial-gradient(circle at 50% 0%, #ff7b00 0%, #111 45%, #050505 100%);
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            padding-top: 20px;
        }

        body::before {
            content: "";
            position: fixed;
            inset: 0;
            background: 
                linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            animation: gridMove 12s linear infinite;
            pointer-events: none;
            z-index: 0;
        }

        @keyframes gridMove {
            from { transform: translateY(0); }
            to { transform: translateY(40px); }
        }

        .container {
            position: relative;
            width: 100%;
            max-width: 1200px;
            backdrop-filter: blur(20px);
            background: rgba(10, 10, 10, 0.92);
            border: 1px solid rgba(255, 140, 0, 0.3);
            border-radius: 24px;
            padding: 30px 28px;
            box-shadow: 
                0 0 40px rgba(255, 120, 0, 0.2),
                inset 0 0 30px rgba(255, 120, 0, 0.05);
            z-index: 2;
            animation: fadeUp 0.6s ease;
        }

        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .logo-section {
            text-align: center;
            margin-bottom: 10px;
        }

        .logo {
            color: #ff9500;
            font-size: 34px;
            font-weight: 900;
            text-shadow: 
                0 0 30px rgba(255, 136, 0, 0.4),
                0 0 60px rgba(255, 136, 0, 0.2);
            letter-spacing: 4px;
        }

        .logo-sub {
            color: #666;
            font-size: 11px;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-top: 2px;
        }

        .divider {
            height: 2px;
            background: linear-gradient(90deg, transparent, #ff9900, transparent);
            margin: 16px 0 24px 0;
            opacity: 0.6;
        }

        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 12px;
            max-width: 400px;
        }

        .toast {
            padding: 16px 22px;
            border-radius: 14px;
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.5px;
            animation: slideIn 0.4s ease;
            box-shadow: 0 8px 32px rgba(0,0,0,0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.08);
        }

        .toast-success {
            background: rgba(0, 200, 83, 0.92);
            color: #fff;
        }

        .toast-error {
            background: rgba(255, 68, 68, 0.92);
            color: #fff;
        }

        .toast-info {
            background: rgba(255, 140, 0, 0.92);
            color: #fff;
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateX(120px); }
            to { opacity: 1; transform: translateX(0); }
        }

        #loginForm {
            max-width: 400px;
            margin: 0 auto;
            padding: 10px 0;
        }

        .field {
            margin-bottom: 16px;
        }

        .field label {
            display: block;
            color: #aaa;
            font-size: 11px;
            letter-spacing: 1.5px;
            margin-bottom: 6px;
            text-transform: uppercase;
        }

        .field input,
        .field textarea,
        .field select {
            width: 100%;
            padding: 14px 18px;
            background: rgba(0, 0, 0, 0.5);
            border: 2px solid #333;
            border-radius: 14px;
            color: #fff;
            font-size: 14px;
            outline: none;
            transition: all 0.3s;
        }

        .field textarea {
            min-height: 100px;
            resize: vertical;
            font-family: sans-serif;
        }

        .field select option {
            background: #1a1a1a;
            color: #fff;
        }

        .field input:focus,
        .field textarea:focus,
        .field select:focus {
            border-color: #ff8c00;
            box-shadow: 0 0 30px rgba(255, 140, 0, 0.1);
        }

        .btn {
            padding: 16px 24px;
            border: none;
            border-radius: 14px;
            background: linear-gradient(135deg, #ff7300, #ffb300);
            color: #fff;
            font-size: 15px;
            font-weight: 700;
            letter-spacing: 1px;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .btn:hover {
            transform: scale(1.02);
            box-shadow: 0 0 40px rgba(255, 140, 0, 0.3);
        }

        .btn:active {
            transform: scale(0.98);
        }

        .btn-sm {
            padding: 10px 18px;
            font-size: 11px;
        }

        .btn-danger {
            background: linear-gradient(135deg, #ff4444, #ff6b6b);
        }
        .btn-danger:hover {
            box-shadow: 0 0 40px rgba(255, 68, 68, 0.3);
        }

        .btn-success {
            background: linear-gradient(135deg, #00c853, #00e676);
        }
        .btn-success:hover {
            box-shadow: 0 0 40px rgba(0, 200, 83, 0.3);
        }

        .btn-outline {
            background: transparent;
            border: 2px solid #ff8c00;
            color: #ff8c00;
        }
        .btn-outline:hover {
            background: rgba(255, 140, 0, 0.1);
            box-shadow: 0 0 30px rgba(255, 140, 0, 0.1);
            transform: scale(1.02);
        }

        .btn-block {
            width: 100%;
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .loading-spinner {
            display: none;
            width: 24px;
            height: 24px;
            border: 3px solid rgba(255,255,255,0.15);
            border-top: 3px solid #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto;
        }

        .btn.loading .loading-spinner {
            display: inline-block;
        }
        .btn.loading .btn-text {
            display: none;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .error {
            color: #ff6b6b;
            font-size: 13px;
            text-align: center;
            margin-top: 12px;
            min-height: 24px;
        }

        .success {
            color: #69db7c;
            font-size: 13px;
            text-align: center;
            margin-top: 12px;
            min-height: 24px;
        }

        .admin-content {
            display: none;
        }

        .admin-content.active {
            display: block;
            animation: fadeUp 0.5s ease;
        }

        .admin-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid rgba(255, 140, 0, 0.1);
        }

        .admin-header .user-info {
            color: #888;
            font-size: 13px;
            letter-spacing: 0.5px;
        }

        .admin-header .user-info span {
            color: #ff9500;
            font-weight: 700;
        }

        .admin-header .stats {
            display: flex;
            gap: 25px;
            flex-wrap: wrap;
        }

        .admin-header .stats .stat-item {
            text-align: center;
        }

        .admin-header .stats .stat-item .num {
            color: #ff9500;
            font-size: 24px;
            font-weight: 900;
        }

        .admin-header .stats .stat-item .label {
            color: #666;
            font-size: 9px;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-top: 2px;
        }

        .header-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .tabs {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255, 140, 0, 0.08);
            padding-bottom: 6px;
        }

        .tab {
            padding: 12px 22px;
            background: transparent;
            border: none;
            color: #666;
            font-size: 12px;
            font-family: 'Orbitron', sans-serif;
            cursor: pointer;
            border-radius: 12px 12px 0 0;
            transition: all 0.3s;
            letter-spacing: 0.5px;
        }

        .tab:hover {
            color: #fff;
            background: rgba(255, 140, 0, 0.05);
        }

        .tab.active {
            color: #ff9500;
            background: rgba(255, 140, 0, 0.08);
            box-shadow: inset 0 -2px 0 #ff9500;
        }

        .tab-content {
            display: none;
            animation: fadeUp 0.3s ease;
        }

        .tab-content.active {
            display: block;
        }

        .card {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 140, 0, 0.06);
            border-radius: 16px;
            padding: 20px 24px;
            margin-bottom: 16px;
            transition: all 0.3s;
        }

        .card:hover {
            border-color: rgba(255, 140, 0, 0.12);
        }

        .card .card-title {
            color: #ff9500;
            font-size: 14px;
            margin-bottom: 14px;
            letter-spacing: 0.5px;
            font-weight: 700;
        }

        .row {
            display: flex;
            gap: 14px;
            flex-wrap: wrap;
            align-items: end;
        }

        .row .field {
            flex: 1;
            min-width: 140px;
            margin-bottom: 0;
        }

        .row .field label {
            font-size: 10px;
            letter-spacing: 1px;
        }

        .row .field input,
        .row .field select {
            padding: 12px 16px;
            font-size: 13px;
        }

        .table-wrap {
            overflow-x: auto;
            border-radius: 12px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }

        table thead {
            background: rgba(255, 140, 0, 0.05);
        }

        table th {
            text-align: left;
            color: #ff9500;
            padding: 12px 14px;
            border-bottom: 2px solid rgba(255, 140, 0, 0.12);
            font-size: 10px;
            letter-spacing: 1px;
            text-transform: uppercase;
            white-space: nowrap;
            font-weight: 700;
        }

        table td {
            padding: 12px 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            color: #ccc;
            vertical-align: middle;
        }

        table tbody tr:hover td {
            background: rgba(255, 140, 0, 0.03);
        }

        .status-badge {
            display: inline-block;
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 9px;
            letter-spacing: 0.5px;
            font-weight: 700;
        }

        .status-active {
            background: rgba(0, 200, 83, 0.15);
            color: #69db7c;
        }

        .status-expired {
            background: rgba(255, 77, 77, 0.15);
            color: #ff6b6b;
        }

        .status-waiting {
            background: rgba(255, 170, 0, 0.15);
            color: #ffb300;
        }

        .status-full {
            background: rgba(255, 100, 0, 0.15);
            color: #ff8800;
        }

        .key-value {
            color: #ff9500;
            font-size: 11px;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            letter-spacing: 0.5px;
        }

        .copy-btn {
            background: none;
            border: none;
            color: #555;
            cursor: pointer;
            font-size: 15px;
            padding: 4px 8px;
            transition: all 0.3s;
            border-radius: 6px;
        }

        .copy-btn:hover {
            color: #ff9500;
            background: rgba(255, 140, 0, 0.1);
        }

        .table-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 14px;
            flex-wrap: wrap;
            align-items: center;
        }

        .table-tab {
            padding: 6px 18px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            color: #777;
            font-size: 10px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Orbitron', sans-serif;
            letter-spacing: 0.5px;
        }

        .table-tab.active {
            background: rgba(255, 140, 0, 0.12);
            border-color: #ff8c00;
            color: #ff9500;
        }

        .table-tab:hover {
            background: rgba(255, 140, 0, 0.06);
        }

        .table-page {
            display: none;
        }
        .table-page.active {
            display: block;
        }

        .search-box {
            display: flex;
            gap: 10px;
            align-items: center;
            flex: 1;
            min-width: 160px;
        }

        .search-box input {
            flex: 1;
            padding: 10px 16px;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid #333;
            border-radius: 12px;
            color: #fff;
            font-size: 12px;
            outline: none;
            transition: all 0.3s;
            font-family: 'Orbitron', sans-serif;
            min-width: 100px;
        }

        .search-box input:focus {
            border-color: #ff8c00;
            box-shadow: 0 0 20px rgba(255, 140, 0, 0.05);
        }

        .export-buttons {
            display: flex;
            gap: 8px;
        }

        .export-buttons .btn-sm {
            padding: 6px 14px;
            font-size: 9px;
            letter-spacing: 0.5px;
        }

        .percent-display {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .percent-display input[type="range"] {
            flex: 1;
            accent-color: #ff8c00;
            background: #333;
            height: 4px;
            border-radius: 4px;
            -webkit-appearance: none;
            appearance: none;
        }

        .percent-display input[type="range"]::-webkit-slider-thumb {
            -webkit-appearance: none;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: #ff8c00;
            cursor: pointer;
            box-shadow: 0 0 20px rgba(255, 140, 0, 0.3);
        }

        .percent-display .percent-value {
            color: #ff9500;
            font-size: 18px;
            font-weight: 700;
            min-width: 50px;
            text-align: center;
        }

        .bulk-actions {
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid rgba(255, 255, 255, 0.04);
        }

        .bulk-actions .btn-sm {
            font-size: 9px;
            padding: 5px 14px;
        }

        .timer-cell {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #69db7c;
        }

        .timer-cell.urgent {
            color: #ff6b6b;
            animation: pulse 1s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #555;
        }

        .empty-state .icon {
            font-size: 40px;
            margin-bottom: 12px;
            opacity: 0.3;
        }

        .empty-state .text {
            font-size: 13px;
        }

        input[type="checkbox"] {
            accent-color: #ff8c00;
            width: 16px;
            height: 16px;
            cursor: pointer;
        }

        .ad-preview {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 20px;
            min-height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #555;
            border: 1px dashed rgba(255, 140, 0, 0.15);
            font-size: 13px;
            transition: all 0.3s;
        }

        .ad-preview.has-content {
            border-color: rgba(255, 140, 0, 0.3);
            color: #fff;
        }

        .notif-item {
            padding: 10px 14px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 10px;
            margin-bottom: 8px;
            border-left: 3px solid #ff8c00;
        }

        .notif-item .text {
            color: #fff;
            font-size: 13px;
            font-family: sans-serif;
        }

        .notif-item .time {
            color: #555;
            font-size: 10px;
            margin-top: 4px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 16px 14px;
                border-radius: 16px;
            }
            
            .admin-header {
                flex-direction: column;
                align-items: stretch;
                gap: 12px;
            }
            
            .admin-header .stats {
                justify-content: space-around;
            }
            
            .header-actions {
                justify-content: center;
            }
            
            .row {
                flex-direction: column;
            }
            
            .row .field {
                min-width: 100%;
            }
            
            table {
                font-size: 10px;
            }
            
            table th,
            table td {
                padding: 8px 10px;
            }
            
            .tabs {
                gap: 4px;
            }
            
            .tab {
                padding: 8px 14px;
                font-size: 10px;
            }
            
            .toast-container {
                top: 10px;
                right: 10px;
                max-width: 280px;
            }
            
            .toast {
                padding: 12px 16px;
                font-size: 11px;
            }
            
            .search-box {
                min-width: 100%;
            }
            
            .export-buttons .btn-sm {
                padding: 4px 10px;
                font-size: 8px;
            }
            
            .logo {
                font-size: 24px;
            }
        }

        @media (max-width: 480px) {
            .admin-header .stats .stat-item .num {
                font-size: 18px;
            }
            
            .admin-header .stats {
                gap: 12px;
            }
            
            table {
                font-size: 9px;
            }
            
            table th,
            table td {
                padding: 6px 8px;
            }
        }

        ::-webkit-scrollbar {
            width: 4px;
            height: 4px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #ff8c00;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #ffa500;
        }

        .flex-between {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }

        .gap-8 {
            gap: 8px;
        }

        .mt-12 {
            margin-top: 12px;
        }

        .text-center {
            text-align: center;
        }

        .text-muted {
            color: #666;
            font-size: 10px;
        }
    </style>
</head>
<body>

    <div class="toast-container" id="toastContainer"></div>

    <div class="container">

        <div class="logo-section">
            <div class="logo">ORANGMODS</div>
            <div class="logo-sub">Admin Panel · Control Center</div>
        </div>
        <div class="divider"></div>

        <div id="loginForm">
            <div class="field">
                <label>👤 Логин</label>
                <input type="text" id="loginInput" placeholder="Введите логин" autocomplete="username" />
            </div>
            <div class="field">
                <label>🔑 Пароль</label>
                <input type="password" id="passInput" placeholder="Введите пароль" autocomplete="current-password" />
            </div>
            <button class="btn btn-block" id="loginBtn">🚀 ВОЙТИ В СИСТЕМУ</button>
            <div class="error" id="errorMsg"></div>
            <div class="success" id="apiStatus"></div>
        </div>

        <div class="admin-content" id="adminContent">

            <div class="admin-header">
                <div class="user-info">
                    👤 Администратор: <span id="userDisplay">Admin</span>
                </div>
                <div class="stats">
                    <div class="stat-item">
                        <div class="num" id="totalKeys">0</div>
                        <div class="label">Всего ключей</div>
                    </div>
                    <div class="stat-item">
                        <div class="num" id="activeKeys">0</div>
                        <div class="label">Активных</div>
                    </div>
                    <div class="stat-item">
                        <div class="num" id="expiredKeys">0</div>
                        <div class="label">Истекших</div>
                    </div>
                    <div class="stat-item">
                        <div class="num" id="totalDevices">0</div>
                        <div class="label">Устройств</div>
                    </div>
                </div>
                <div class="header-actions">
                    <button class="btn btn-sm btn-outline" id="refreshBtn" title="Обновить">🔄</button>
                    <button class="btn btn-sm btn-danger" id="logoutBtn" style="width:auto;padding:6px 16px;font-size:10px;">🚪 ВЫЙТИ</button>
                </div>
            </div>

            <div class="tabs">
                <button class="tab active" data-tab="tab1">📋 Ключи</button>
                <button class="tab" data-tab="tab2">➕ Создать</button>
                <button class="tab" data-tab="tab3">📢 Уведомления</button>
                <button class="tab" data-tab="tab4">🎯 Реклама</button>
            </div>

            <div class="tab-content active" id="tab1">
                <div class="card">
                    <div class="table-tabs">
                        <button class="table-tab active" data-page="page1">🟢 Активные / Ожидают</button>
                        <button class="table-tab" data-page="page2">🔴 Истекшие</button>
                        <div class="search-box">
                            <input type="text" id="searchInput" placeholder="🔍 Поиск по ключу или названию..." />
                        </div>
                        <div class="export-buttons">
                            <button class="btn btn-sm btn-outline" id="exportCSV">CSV</button>
                            <button class="btn btn-sm btn-outline" id="exportJSON">JSON</button>
                        </div>
                    </div>

                    <div class="table-page active" id="page1">
                        <div class="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th style="width:32px;">
                                            <input type="checkbox" id="selectAllActive" />
                                        </th>
                                        <th>Ключ</th>
                                        <th>Название</th>
                                        <th>Тип</th>
                                        <th>%</th>
                                        <th>Запуск</th>
                                        <th>Остаток</th>
                                        <th>Слоты</th>
                                        <th>Статус</th>
                                        <th style="width:44px;"></th>
                                    </tr>
                                </thead>
                                <tbody id="activeKeysTable"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="table-page" id="page2">
                        <div class="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th style="width:32px;">
                                            <input type="checkbox" id="selectAllExpired" />
                                        </th>
                                        <th>Ключ</th>
                                        <th>Название</th>
                                        <th>Тип</th>
                                        <th>%</th>
                                        <th>Запуск</th>
                                        <th>Остаток</th>
                                        <th>Слоты</th>
                                        <th>Статус</th>
                                        <th style="width:44px;"></th>
                                    </tr>
                                </thead>
                                <tbody id="expiredKeysTable"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="bulk-actions">
                        <span style="color:#666;font-size:10px;">Выбрано: <span id="selectedCount" style="color:#ff9500;font-weight:700;">0</span></span>
                        <button class="btn btn-sm btn-danger" id="bulkDeleteBtn">🗑️ Удалить выбранные</button>
                    </div>
                </div>
            </div>

            <div class="tab-content" id="tab2">
                <div class="card">
                    <div class="card-title">🔑 Создать новый ключ</div>
                    <div class="row">
                        <div class="field">
                            <label>Название</label>
                            <input type="text" id="keyName" placeholder="Например: Промо 7 дней" />
                        </div>
                        <div class="field" style="min-width:110px;">
                            <label>Тип</label>
                            <select id="keyType">
                                <option value="DAY">📅 Дни</option>
                                <option value="HOUR">⏰ Часы</option>
                            </select>
                        </div>
                        <div class="field" style="min-width:90px;">
                            <label>Кол-во</label>
                            <input type="number" id="keyDuration" value="7" min="1" max="365" />
                        </div>
                        <div class="field" style="min-width:90px;">
                            <label>Устройств</label>
                            <input type="number" id="keyDevices" value="5" min="1" max="999" />
                        </div>
                    </div>
                    <div class="row" style="margin-top:12px;">
                        <div class="field" style="min-width:200px;flex:2;">
                            <label>Ограничение % (40-95)</label>
                            <div class="percent-display">
                                <input type="range" min="40" max="95" value="70" id="keyPercentRange" />
                                <span class="percent-value" id="keyPercentDisplay">70%</span>
                            </div>
                        </div>
                        <div class="field" style="min-width:130px;flex:0;">
                            <label>Авто-название</label>
                            <button class="btn btn-sm btn-outline" id="generateAutoBtn" style="width:100%;margin-top:0;">🎲 Сгенерировать</button>
                        </div>
                    </div>
                    <button class="btn btn-sm btn-success" id="generateKeyBtn" style="margin-top:14px;width:100%;">
                        <span class="btn-text">➕ Сгенерировать ключ</span>
                        <span class="loading-spinner"></span>
                    </button>
                    <div class="success" id="keyGenResult"></div>
                </div>

                <div class="card">
                    <div class="card-title">🗑️ Удалить ключ по значению</div>
                    <div class="row">
                        <div class="field">
                            <label>Введите ключ</label>
                            <input type="text" id="deleteKeyInput" placeholder="OrangMods-7DAY-XXXXXX" />
                        </div>
                        <button class="btn btn-sm btn-danger" id="deleteKeyBtn" style="min-width:120px;">🗑️ Удалить</button>
                    </div>
                    <div class="error" id="deleteResult"></div>
                </div>
            </div>

            <div class="tab-content" id="tab3">
                <div class="card">
                    <div class="card-title">📢 Отправить уведомление</div>
                    <div class="field">
                        <label>Текст уведомления</label>
                        <textarea id="notifyText" placeholder="Введите текст уведомления для всех пользователей..."></textarea>
                    </div>
                    <button class="btn btn-sm btn-success" id="sendNotifyBtn">
                        <span class="btn-text">📨 Отправить всем</span>
                        <span class="loading-spinner"></span>
                    </button>
                    <div class="success" id="notifyResult"></div>
                </div>
                <div class="card">
                    <div class="card-title">📋 История уведомлений</div>
                    <div id="notifyHistory">
                        <div class="empty-state">
                            <div class="icon">📭</div>
                            <div class="text">Пока нет отправленных уведомлений</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="tab-content" id="tab4">
                <div class="card">
                    <div class="card-title">🎯 Настройка рекламы</div>
                    <div class="field">
                        <label>HTML-код рекламы</label>
                        <textarea id="adHtml" placeholder="<div style='background:linear-gradient...'>Рекламный баннер</div>"></textarea>
                    </div>
                    <div class="row">
                        <div class="field" style="min-width:160px;flex:0;">
                            <label>Закрываемая?</label>
                            <select id="adClosable">
                                <option value="1">✅ Да</option>
                                <option value="0">❌ Нет</option>
                            </select>
                        </div>
                        <button class="btn btn-sm btn-success" id="saveAdBtn" style="min-width:130px;">
                            <span class="btn-text">💾 Сохранить</span>
                            <span class="loading-spinner"></span>
                        </button>
                    </div>
                    <div class="success" id="adResult"></div>
                </div>
                <div class="card">
                    <div class="card-title">👁️ Предпросмотр</div>
                    <div id="adPreview" class="ad-preview">
                        <span>Реклама не настроена</span>
                    </div>
                    <div style="margin-top:12px;display:flex;gap:14px;flex-wrap:wrap;">
                        <label style="color:#888;font-size:11px;display:flex;align-items:center;gap:8px;cursor:pointer;">
                            <input type="checkbox" id="adShowPreview" checked /> Показывать предпросмотр
                        </label>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <script>
        (function() {
            'use strict';

            class Api {
                constructor() {
                    this.base = '/api';
                    this.token = null;
                }

                async _fetch(endpoint, options = {}) {
                    const url = this.base + endpoint;
                    const headers = {
                        'Content-Type': 'application/json',
                        ...options.headers
                    };
                    if (this.token) {
                        headers['Authorization'] = 'Bearer ' + this.token;
                    }

                    const config = { ...options, headers };
                    const response = await fetch(url, config);

                    if (response.status === 401) {
                        if (this.onUnauthorized) this.onUnauthorized();
                        throw new Error('Token expired');
                    }

                    let data;
                    const contentType = response.headers.get('content-type');
                    if (contentType && contentType.includes('application/json')) {
                        data = await response.json();
                    } else {
                        data = await response.text();
                    }

                    if (!response.ok) {
                        const msg = data?.detail || data?.error || data || 'Server error';
                        throw new Error(msg);
                    }

                    return data;
                }

                async info() { return this._fetch('/info'); }

                async login(login, password) {
                    const data = await this._fetch('/login', {
                        method: 'POST',
                        body: JSON.stringify({ login, password })
                    });
                    if (data.success && data.token) {
                        this.token = data.token;
                    }
                    return data;
                }

                async dashboard() { return this._fetch('/dashboard'); }

                async getKeys() { return this._fetch('/keys'); }

                async createKey(name, type, duration, maxDevices, maxPercent) {
                    return this._fetch('/keys', {
                        method: 'POST',
                        body: JSON.stringify({
                            name,
                            type,
                            duration,
                            max_devices: maxDevices,
                            max_percent: maxPercent
                        })
                    });
                }

                async deleteKey(id) {
                    return this._fetch(`/keys/${id}`, { method: 'DELETE' });
                }

                async getNotifications() { return this._fetch('/notifications'); }

                async sendNotification(text) {
                    return this._fetch('/notifications', {
                        method: 'POST',
                        body: JSON.stringify({ text })
                    });
                }

                async getAds() { return this._fetch('/ads'); }

                async saveAds(html, isClosable) {
                    return this._fetch('/ads', {
                        method: 'POST',
                        body: JSON.stringify({ html, is_closable: isClosable })
                    });
                }
            }

            const api = new Api();

            const loginForm = document.getElementById('loginForm');
            const adminContent = document.getElementById('adminContent');
            const loginInput = document.getElementById('loginInput');
            const passInput = document.getElementById('passInput');
            const loginBtn = document.getElementById('loginBtn');
            const errorMsg = document.getElementById('errorMsg');
            const apiStatus = document.getElementById('apiStatus');

            const userDisplay = document.getElementById('userDisplay');
            const totalKeysEl = document.getElementById('totalKeys');
            const activeKeysEl = document.getElementById('activeKeys');
            const expiredKeysEl = document.getElementById('expiredKeys');
            const totalDevicesEl = document.getElementById('totalDevices');

            const searchInput = document.getElementById('searchInput');
            const activeKeysTable = document.getElementById('activeKeysTable');
            const expiredKeysTable = document.getElementById('expiredKeysTable');
            const selectAllActive = document.getElementById('selectAllActive');
            const selectAllExpired = document.getElementById('selectAllExpired');
            const selectedCount = document.getElementById('selectedCount');
            const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');

            const keyName = document.getElementById('keyName');
            const keyType = document.getElementById('keyType');
            const keyDuration = document.getElementById('keyDuration');
            const keyDevices = document.getElementById('keyDevices');
            const keyPercentRange = document.getElementById('keyPercentRange');
            const keyPercentDisplay = document.getElementById('keyPercentDisplay');
            const generateKeyBtn = document.getElementById('generateKeyBtn');
            const keyGenResult = document.getElementById('keyGenResult');

            const deleteKeyInput = document.getElementById('deleteKeyInput');
            const deleteKeyBtn = document.getElementById('deleteKeyBtn');
            const deleteResult = document.getElementById('deleteResult');

            const notifyText = document.getElementById('notifyText');
            const sendNotifyBtn = document.getElementById('sendNotifyBtn');
            const notifyResult = document.getElementById('notifyResult');
            const notifyHistory = document.getElementById('notifyHistory');

            const adHtml = document.getElementById('adHtml');
            const adClosable = document.getElementById('adClosable');
            const saveAdBtn = document.getElementById('saveAdBtn');
            const adResult = document.getElementById('adResult');
            const adPreview = document.getElementById('adPreview');
            const adShowPreview = document.getElementById('adShowPreview');

            const refreshBtn = document.getElementById('refreshBtn');
            const logoutBtn = document.getElementById('logoutBtn');

            let cache = {
                keys: [],
                notifications: [],
                ads: { html: '', is_closable: true },
                stats: {}
            };

            let selectedActiveSet = new Set();
            let selectedExpiredSet = new Set();

            function showToast(message, type = 'info') {
                const container = document.getElementById('toastContainer');
                const toast = document.createElement('div');
                toast.className = `toast toast-${type}`;
                toast.textContent = message;
                container.appendChild(toast);
                setTimeout(() => {
                    toast.style.opacity = '0';
                    toast.style.transform = 'translateX(120px)';
                    setTimeout(() => toast.remove(), 400);
                }, 4000);
            }

            function renderKeys(search = '') {
                const searchLower = search.toLowerCase();
                const filtered = cache.keys.filter(k => {
                    const match = k.key_value.toLowerCase().includes(searchLower) ||
                        (k.name && k.name.toLowerCase().includes(searchLower));
                    return match;
                });

                const active = filtered.filter(k => k.status !== 'expired');
                const expired = filtered.filter(k => k.status === 'expired');

                if (active.length === 0) {
                    activeKeysTable.innerHTML = `
                        <tr>
                            <td colspan="10">
                                <div class="empty-state">
                                    <div class="icon">📭</div>
                                    <div class="text">Нет активных ключей</div>
                                </div>
                            </td>
                        </tr>
                    `;
                } else {
                    activeKeysTable.innerHTML = active.map(k => renderKeyRow(k)).join('');
                }

                if (expired.length === 0) {
                    expiredKeysTable.innerHTML = `
                        <tr>
                            <td colspan="10">
                                <div class="empty-state">
                                    <div class="icon">🎉</div>
                                    <div class="text">Нет истекших ключей</div>
                                </div>
                            </td>
                        </tr>
                    `;
                } else {
                    expiredKeysTable.innerHTML = expired.map(k => renderKeyRow(k)).join('');
                }

                totalKeysEl.textContent = cache.keys.length;
                activeKeysEl.textContent = active.length;
                expiredKeysEl.textContent = expired.length;
                totalDevicesEl.textContent = cache.stats?.total_devices || 0;
                updateSelectedCount();

                document.querySelectorAll('.copy-btn').forEach(btn => {
                    btn.addEventListener('click', function(e) {
                        e.stopPropagation();
                        const key = this.dataset.key;
                        navigator.clipboard.writeText(key).then(() => {
                            showToast('✅ Ключ скопирован!', 'success');
                        }).catch(() => {
                            const input = document.createElement('input');
                            input.value = key;
                            document.body.appendChild(input);
                            input.select();
                            document.execCommand('copy');
                            input.remove();
                            showToast('✅ Ключ скопирован!', 'success');
                        });
                    });
                });

                document.querySelectorAll('.key-checkbox').forEach(cb => {
                    cb.addEventListener('change', function() {
                        const key = this.dataset.key;
                        const status = this.dataset.status;
                        if (status === 'expired') {
                            if (this.checked) selectedExpiredSet.add(key);
                            else selectedExpiredSet.delete(key);
                        } else {
                            if (this.checked) selectedActiveSet.add(key);
                            else selectedActiveSet.delete(key);
                        }
                        updateSelectedCount();
                    });
                });
            }

            function renderKeyRow(key) {
                const statusMap = {
                    'active': { text: '🟢 Активен', class: 'status-active' },
                    'waiting': { text: '🟡 Ожидает', class: 'status-waiting' },
                    'expired': { text: '🔴 Истек', class: 'status-expired' },
                    'full': { text: '🟠 Полный', class: 'status-full' }
                };
                const s = statusMap[key.status] || statusMap['waiting'];

                let timerClass = 'timer-cell';
                if (key.status === 'active' && key.time_left_seconds < 3600) {
                    timerClass += ' urgent';
                }

                const isActive = key.status !== 'expired';
                const isChecked = isActive ?
                    selectedActiveSet.has(key.key_value) :
                    selectedExpiredSet.has(key.key_value);

                return `
                    <tr>
                        <td>
                            <input type="checkbox" class="key-checkbox" 
                                   data-key="${key.key_value}" 
                                   data-status="${key.status}"
                                   ${isChecked ? 'checked' : ''} />
                        </td>
                        <td class="key-value">
                            ${key.key_value}
                            <button class="copy-btn" data-key="${key.key_value}" title="Копировать ключ">📋</button>
                        </td>
                        <td>${key.name || '-'}</td>
                        <td>${key.type === 'DAY' ? '📅 Дни' : '⏰ Часы'}</td>
                        <td style="color:#ff9500;font-weight:700;">${key.max_percent || 95}%</td>
                        <td>${key.first_activation || 'НЕТ'}</td>
                        <td class="${timerClass}">${key.time_left || 'НЕТ'}</td>
                        <td>${key.used_devices || 0}/${key.max_devices || 0}</td>
                        <td><span class="status-badge ${s.class}">${s.text}</span></td>
                        <td>
                            <button class="copy-btn" data-key="${key.key_value}" title="Копировать ключ">📋</button>
                        </td>
                    </tr>
                `;
            }

            function renderNotifications() {
                if (cache.notifications.length === 0) {
                    notifyHistory.innerHTML = `
                        <div class="empty-state">
                            <div class="icon">📭</div>
                            <div class="text">Пока нет отправленных уведомлений</div>
                        </div>
                    `;
                    return;
                }
                notifyHistory.innerHTML = cache.notifications.slice().reverse().map(n => `
                    <div class="notif-item">
                        <div class="text">${n.text}</div>
                        <div class="time">📅 ${new Date(n.created_at).toLocaleString('ru-RU')}</div>
                    </div>
                `).join('');
            }

            function renderAd() {
                const show = adShowPreview.checked;
                if (!show || !cache.ads.html) {
                    adPreview.innerHTML = `<span>${cache.ads.html ? 'Предпросмотр отключен' : 'Реклама не настроена'}</span>`;
                    adPreview.className = 'ad-preview';
                    return;
                }
                adPreview.innerHTML = cache.ads.html;
                adPreview.className = 'ad-preview has-content';
                adHtml.value = cache.ads.html || '';
                adClosable.value = cache.ads.is_closable ? '1' : '0';
            }

            function updateSelectedCount() {
                const total = selectedActiveSet.size + selectedExpiredSet.size;
                selectedCount.textContent = total;
            }

            async function loadDashboard() {
                try {
                    const data = await api.dashboard();
                    cache.stats = data.stats || {};
                    cache.keys = data.keys || [];
                    cache.notifications = data.notifications || [];
                    cache.ads = data.ads || { html: '', is_closable: true };
                    renderAll();
                    showToast('✅ Данные обновлены', 'success');
                } catch (err) {
                    if (err.message === 'Token expired') {
                    } else {
                        showToast('❌ Ошибка загрузки: ' + err.message, 'error');
                    }
                    throw err;
                }
            }

            async function loadKeysOnly() {
                try {
                    const data = await api.getKeys();
                    cache.keys = data.keys || [];
                    renderKeys(searchInput.value.trim());
                } catch (err) {
                    if (err.message !== 'Token expired') {
                        showToast('❌ Ошибка загрузки ключей: ' + err.message, 'error');
                    }
                }
            }

            async function loadNotificationsOnly() {
                try {
                    const data = await api.getNotifications();
                    cache.notifications = data.notifications || [];
                    renderNotifications();
                } catch (err) {
                    if (err.message !== 'Token expired') {
                        showToast('❌ Ошибка загрузки уведомлений: ' + err.message, 'error');
                    }
                }
            }

            async function loadAdsOnly() {
                try {
                    const data = await api.getAds();
                    cache.ads = data || { html: '', is_closable: true };
                    renderAd();
                } catch (err) {
                    if (err.message !== 'Token expired') {
                        showToast('❌ Ошибка загрузки рекламы: ' + err.message, 'error');
                    }
                }
            }

            async function updateStatsOnly() {
                try {
                    const data = await api.dashboard();
                    cache.stats = data.stats || {};
                    totalKeysEl.textContent = cache.stats.total_keys || 0;
                    activeKeysEl.textContent = cache.stats.active_keys || 0;
                    expiredKeysEl.textContent = cache.stats.expired_keys || 0;
                    totalDevicesEl.textContent = cache.stats.total_devices || 0;
                } catch (err) {
                    if (err.message !== 'Token expired') {
                        showToast('❌ Ошибка обновления статистики: ' + err.message, 'error');
                    }
                }
            }

            function renderAll() {
                renderKeys(searchInput.value.trim());
                renderNotifications();
                renderAd();
            }

            api.onUnauthorized = function() {
                showToast('⏳ Сессия истекла, войдите снова', 'error');
                logout();
            };

            async function checkApiAvailability() {
                try {
                    await api.info();
                    apiStatus.textContent = '✅ API доступен';
                    apiStatus.style.color = '#69db7c';
                    return true;
                } catch (e) {
                    apiStatus.textContent = '❌ Server Offline';
                    apiStatus.style.color = '#ff6b6b';
                    showToast('❌ Сервер недоступен', 'error');
                    return false;
                }
            }

            async function attemptLogin() {
                const login = loginInput.value.trim();
                const pass = passInput.value.trim();

                if (!login || !pass) {
                    errorMsg.textContent = '⚠️ Заполните все поля';
                    return;
                }

                errorMsg.textContent = '';
                loginBtn.classList.add('loading');

                try {
                    const data = await api.login(login, pass);
                    if (data.success && data.token) {
                        showAdminPanel();
                        showToast('✅ Добро пожаловать!', 'success');
                        await loadDashboard();
                    } else {
                        errorMsg.textContent = '❌ ' + (data.error || 'Ошибка входа');
                        showToast('❌ Ошибка входа', 'error');
                    }
                } catch (err) {
                    errorMsg.textContent = '❌ ' + err.message;
                    showToast('❌ Ошибка: ' + err.message, 'error');
                }

                loginBtn.classList.remove('loading');
            }

            function showAdminPanel() {
                loginForm.style.display = 'none';
                adminContent.classList.add('active');
                userDisplay.textContent = loginInput.value.trim() || 'Admin';
            }

            function logout() {
                api.token = null;
                loginForm.style.display = 'block';
                adminContent.classList.remove('active');
                loginInput.value = '';
                passInput.value = '';
                errorMsg.textContent = '';
                cache = { keys: [], notifications: [], ads: { html: '', is_closable: true }, stats: {} };
                selectedActiveSet.clear();
                selectedExpiredSet.clear();
                renderAll();
                showToast('👋 Вы вышли из системы', 'info');
            }

            function exportData(format) {
                const data = cache.keys.map(k => ({
                    key: k.key_value,
                    name: k.name || '-',
                    type: k.type,
                    duration: k.duration,
                    max_devices: k.max_devices,
                    max_percent: k.max_percent || 95,
                    used_devices: k.used_devices || 0,
                    first_activation: k.first_activation || 'НЕТ',
                    time_left: k.time_left || 'НЕТ',
                    status: k.status || 'unknown'
                }));

                if (format === 'CSV') {
                    const headers = ['Ключ', 'Название', 'Тип', 'Кол-во', 'Устройств', '%', 'Использовано', 'Запуск', 'Остаток',
                        'Статус'
                    ];
                    const rows = data.map(d => [
                        d.key, d.name, d.type, d.duration, d.max_devices, d.max_percent,
                        d.used_devices, d.first_activation, d.time_left, d.status
                    ]);
                    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
                    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
                    const link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = `keys_${new Date().toISOString().slice(0,10)}.csv`;
                    link.click();
                    showToast('✅ CSV экспортирован', 'success');
                } else {
                    const json = JSON.stringify(data, null, 2);
                    const blob = new Blob([json], { type: 'application/json' });
                    const link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = `keys_${new Date().toISOString().slice(0,10)}.json`;
                    link.click();
                    showToast('✅ JSON экспортирован', 'success');
                }
            }

            loginBtn.addEventListener('click', attemptLogin);
            [loginInput, passInput].forEach(f => {
                f.addEventListener('keydown', e => {
                    if (e.key === 'Enter') loginBtn.click();
                });
            });

            logoutBtn.addEventListener('click', logout);

            refreshBtn.addEventListener('click', async function() {
                this.classList.add('loading');
                try { await loadDashboard(); } catch (e) {}
                this.classList.remove('loading');
            });

            searchInput.addEventListener('input', function() {
                renderKeys(this.value.trim());
            });

            document.getElementById('exportCSV').addEventListener('click', () => exportData('CSV'));
            document.getElementById('exportJSON').addEventListener('click', () => exportData('JSON'));

            selectAllActive.addEventListener('change', function() {
                document.querySelectorAll('#activeKeysTable .key-checkbox').forEach(cb => {
                    cb.checked = this.checked;
                    const key = cb.dataset.key;
                    if (this.checked) selectedActiveSet.add(key);
                    else selectedActiveSet.delete(key);
                });
                updateSelectedCount();
            });

            selectAllExpired.addEventListener('change', function() {
                document.querySelectorAll('#expiredKeysTable .key-checkbox').forEach(cb => {
                    cb.checked = this.checked;
                    const key = cb.dataset.key;
                    if (this.checked) selectedExpiredSet.add(key);
                    else selectedExpiredSet.delete(key);
                });
                updateSelectedCount();
            });

            bulkDeleteBtn.addEventListener('click', async function() {
                const total = selectedActiveSet.size + selectedExpiredSet.size;
                if (total === 0) {
                    showToast('⚠️ Ничего не выбрано', 'error');
                    return;
                }
                if (!confirm(`Удалить ${total} ключей?`)) return;

                const idsToDelete = [];
                const allKeys = cache.keys;
                [...selectedActiveSet, ...selectedExpiredSet].forEach(keyVal => {
                    const found = allKeys.find(k => k.key_value === keyVal);
                    if (found && found.id) idsToDelete.push(found.id);
                });

                let deleted = 0;
                for (const id of idsToDelete) {
                    try {
                        await api.deleteKey(id);
                        deleted++;
                    } catch (err) {
                        showToast('❌ Ошибка удаления: ' + err.message, 'error');
                    }
                }

                selectedActiveSet.clear();
                selectedExpiredSet.clear();
                await loadKeysOnly();
                await updateStatsOnly();
                showToast(`✅ Удалено ${deleted} ключей`, 'success');
            });

            document.getElementById('generateAutoBtn').addEventListener('click', function() {
                const prefixes = ['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Zeta', 'Eta', 'Theta',
                    'Iota', 'Kappa', 'Lambda', 'Mu', 'Nu', 'Xi', 'Omicron', 'Pi', 'Rho', 'Sigma',
                    'Tau', 'Upsilon', 'Phi', 'Chi', 'Psi', 'Omega'
                ];
                const suffixes = ['Pro', 'Ultra', 'Max', 'Prime', 'Elite', 'Core', 'Nova', 'Apex', 'Zen', 'Flux'];
                const name = prefixes[Math.floor(Math.random() * prefixes.length)] + ' ' +
                    suffixes[Math.floor(Math.random() * suffixes.length)];
                keyName.value = name;
                showToast('🎲 Авто-название сгенерировано', 'info');
            });

            keyPercentRange.addEventListener('input', function() {
                keyPercentDisplay.textContent = this.value + '%';
            });

            generateKeyBtn.addEventListener('click', async function() {
                const name = keyName.value.trim() || 'Без названия';
                const type = keyType.value;
                const duration = parseInt(keyDuration.value) || 7;
                const devices = parseInt(keyDevices.value) || 5;
                const maxPercent = parseInt(keyPercentRange.value) || 70;

                if (duration < 1 || duration > 365) {
                    showToast('⚠️ Количество от 1 до 365', 'error');
                    return;
                }
                if (devices < 1 || devices > 999) {
                    showToast('⚠️ Устройств от 1 до 999', 'error');
                    return;
                }

                this.classList.add('loading');
                try {
                    const result = await api.createKey(name, type, duration, devices, maxPercent);
                    keyGenResult.textContent = `✅ Ключ создан: ${result.key_value} (${maxPercent}%)`;
                    keyGenResult.style.color = '#69db7c';
                    keyName.value = '';
                    showToast(`✅ Ключ создан: ${result.key_value}`, 'success');
                    await loadKeysOnly();
                    await updateStatsOnly();
                } catch (err) {
                    showToast('❌ Ошибка создания: ' + err.message, 'error');
                    keyGenResult.textContent = '❌ ' + err.message;
                    keyGenResult.style.color = '#ff6b6b';
                }
                this.classList.remove('loading');
            });

            deleteKeyBtn.addEventListener('click', async function() {
                const keyValue = deleteKeyInput.value.trim();
                if (!keyValue) {
                    deleteResult.textContent = '⚠️ Введите ключ';
                    deleteResult.style.color = '#ff6b6b';
                    showToast('⚠️ Введите ключ', 'error');
                    return;
                }

                const found = cache.keys.find(k => k.key_value === keyValue);
                if (!found) {
                    deleteResult.textContent = '❌ Ключ не найден';
                    deleteResult.style.color = '#ff6b6b';
                    showToast('❌ Ключ не найден', 'error');
                    return;
                }

                try {
                    await api.deleteKey(found.id);
                    deleteResult.textContent = '✅ Ключ удален';
                    deleteResult.style.color = '#69db7c';
                    deleteKeyInput.value = '';
                    showToast('✅ Ключ удален', 'success');
                    await loadKeysOnly();
                    await updateStatsOnly();
                } catch (err) {
                    deleteResult.textContent = '❌ ' + err.message;
                    deleteResult.style.color = '#ff6b6b';
                    showToast('❌ Ошибка удаления: ' + err.message, 'error');
                }
            });

            sendNotifyBtn.addEventListener('click', async function() {
                const text = notifyText.value.trim();
                if (!text) {
                    notifyResult.textContent = '⚠️ Введите текст';
                    notifyResult.style.color = '#ff6b6b';
                    showToast('⚠️ Введите текст', 'error');
                    return;
                }

                this.classList.add('loading');
                try {
                    await api.sendNotification(text);
                    notifyResult.textContent = '✅ Уведомление отправлено!';
                    notifyResult.style.color = '#69db7c';
                    notifyText.value = '';
                    showToast('📨 Уведомление отправлено', 'success');
                    await loadNotificationsOnly();
                } catch (err) {
                    notifyResult.textContent = '❌ ' + err.message;
                    notifyResult.style.color = '#ff6b6b';
                    showToast('❌ Ошибка: ' + err.message, 'error');
                }
                this.classList.remove('loading');
            });

            saveAdBtn.addEventListener('click', async function() {
                const html = adHtml.value.trim();
                const isClosable = adClosable.value === '1';

                this.classList.add('loading');
                try {
                    await api.saveAds(html, isClosable);
                    adResult.textContent = '✅ Реклама сохранена';
                    adResult.style.color = '#69db7c';
                    showToast('✅ Реклама сохранена', 'success');
                    await loadAdsOnly();
                } catch (err) {
                    adResult.textContent = '❌ ' + err.message;
                    adResult.style.color = '#ff6b6b';
                    showToast('❌ Ошибка: ' + err.message, 'error');
                }
                this.classList.remove('loading');
            });

            adShowPreview.addEventListener('change', renderAd);

            function initTabs() {
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.addEventListener('click', function() {
                        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                        this.classList.add('active');
                        document.getElementById(this.dataset.tab).classList.add('active');
                    });
                });

                document.querySelectorAll('.table-tab').forEach(tab => {
                    tab.addEventListener('click', function() {
                        document.querySelectorAll('.table-tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.table-page').forEach(p => p.classList.remove('active'));
                        this.classList.add('active');
                        document.getElementById(this.dataset.page).classList.add('active');
                    });
                });
            }

            (async function init() {
                initTabs();

                const available = await checkApiAvailability();
                if (!available) {
                    loginBtn.disabled = true;
                    loginBtn.style.opacity = '0.5';
                    loginBtn.textContent = '🚫 Server Offline';
                } else {
                    loginBtn.disabled = false;
                    loginBtn.style.opacity = '1';
                    loginBtn.textContent = '🚀 ВОЙТИ В СИСТЕМУ';
                }

                console.log('🔐 OrangMods Admin Panel v1.0');
                console.log('🌐 API Base:', api.base);
            })();

        })();
    </script>
</body>
</html>"""

# ============================================================
# СОХРАНЕНИЕ HTML
# ============================================================

with open(STATIC_DIR / "index.html", "w", encoding="utf-8") as f:
    f.write(ADMIN_HTML)

# ============================================================
# API МАРШРУТЫ
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def serve_admin():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
async def health_check():
    try:
        conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
        try:
            await conn.fetchrow("SELECT 1")
            return {"status": "ok", "timestamp": datetime.now().isoformat()}
        finally:
            await conn.close()
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )

@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

@app.get("/api/info")
async def api_info():
    return {"status": "online", "version": "1.0.0", "timestamp": datetime.now().isoformat()}

@app.post("/api/login")
async def admin_login(login_data: AdminLogin, request: Request):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash FROM admins WHERE username = $1 AND is_active = true",
            login_data.login
        )
        if not row or not verify_password(login_data.password, row['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"sub": str(row['id']), "username": row['username']})
        
        client_ip = request.client.host if request.client else "unknown"
        await log_action(row['id'], "login", f"Login from {client_ip}", client_ip)
        
        return {"success": True, "token": token, "username": row['username']}
    finally:
        await conn.close()

# ============================================================
# API - ДАШБОРД
# ============================================================

@app.get("/api/dashboard")
async def get_dashboard(current_admin: dict = Depends(get_current_admin)):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        # Статистика
        total_keys = await conn.fetchval("SELECT COUNT(*) FROM keys")
        active_keys = await conn.fetchval("SELECT COUNT(*) FROM keys WHERE status = 'active'")
        expired_keys = await conn.fetchval("SELECT COUNT(*) FROM keys WHERE status = 'expired'")
        total_devices = await conn.fetchval("SELECT COALESCE(SUM(used_devices), 0) FROM keys")
        
        stats = {
            "total_keys": total_keys or 0,
            "active_keys": active_keys or 0,
            "expired_keys": expired_keys or 0,
            "total_devices": total_devices or 0
        }
        
        # Ключи
        rows = await conn.fetch("""
            SELECT id, key_value, name, type, duration, max_devices, max_percent, 
                   used_devices, first_activation, status, created_at
            FROM keys
            ORDER BY created_at DESC
        """)
        keys_list = []
        for row in rows:
            key_dict = dict(row)
            time_info = calculate_time_left(key_dict)
            key_dict.update(time_info)
            keys_list.append(key_dict)
        
        # Уведомления
        rows = await conn.fetch("SELECT id, text, created_at FROM notifications ORDER BY created_at DESC LIMIT 50")
        notifications = [{"id": row['id'], "text": row['text'], "created_at": row['created_at']} for row in rows]
        
        # Реклама
        row = await conn.fetchrow("SELECT html, is_closable FROM advertisements WHERE is_active = true ORDER BY updated_at DESC LIMIT 1")
        ads = {"html": row['html'] if row else "", "is_closable": bool(row['is_closable']) if row else True}
        
        # Логи
        rows = await conn.fetch("""
            SELECT l.*, a.username 
            FROM logs l 
            LEFT JOIN admins a ON l.admin_id = a.id 
            ORDER BY l.created_at DESC LIMIT 10
        """)
        logs = []
        for row in rows:
            logs.append({
                "id": row['id'],
                "admin": row['username'] if row.get('username') else "System",
                "action": row['action'],
                "details": row['details'],
                "created_at": row['created_at']
            })
        
        return {
            "stats": stats,
            "keys": keys_list,
            "notifications": notifications,
            "ads": ads,
            "logs": logs
        }
    finally:
        await conn.close()

# ============================================================
# API - КЛЮЧИ
# ============================================================

@app.get("/api/keys")
async def get_keys(current_admin: dict = Depends(get_current_admin)):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        rows = await conn.fetch("""
            SELECT id, key_value, name, type, duration, max_devices, max_percent, 
                   used_devices, first_activation, status, created_at
            FROM keys
            ORDER BY created_at DESC
            LIMIT $1
        """, MAX_LIMIT)
        
        keys_list = []
        for row in rows:
            key_dict = dict(row)
            time_info = calculate_time_left(key_dict)
            key_dict.update(time_info)
            keys_list.append(key_dict)
        
        return {"keys": keys_list}
    finally:
        await conn.close()

@app.post("/api/keys")
async def create_key(key_data: KeyCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    key_value = generate_key_code(key_data.type, key_data.duration)
    
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow("""
            INSERT INTO keys (key_value, name, type, duration, max_devices, max_percent, status, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, 'waiting', $7)
            RETURNING id
        """, key_value, key_data.name, key_data.type, key_data.duration, key_data.max_devices, key_data.max_percent, current_admin["id"])
        
        client_ip = request.client.host if request else "unknown"
        await log_action(current_admin["id"], "create_key", f"Created key: {key_value}", client_ip)
        
        return {
            "id": row['id'],
            "key_value": key_value,
            "name": key_data.name,
            "type": key_data.type,
            "duration": key_data.duration,
            "max_devices": key_data.max_devices,
            "max_percent": key_data.max_percent,
            "status": "waiting"
        }
    finally:
        await conn.close()

@app.delete("/api/keys/{key_id}")
async def delete_key(
    key_id: int, 
    force: bool = False,
    current_admin: dict = Depends(get_current_admin), 
    request: Request = None
):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        # Получаем информацию о ключе
        row = await conn.fetchrow("SELECT key_value, status FROM keys WHERE id = $1", key_id)
        if not row:
            raise HTTPException(status_code=404, detail="Key not found")
        
        key_value = row['key_value']
        key_status = row['status']
        
        # Если ключ активный и force=True - отправляем уведомление
        if key_status == 'active' and force:
            # Находим все устройства, использующие этот ключ
            devices = await conn.fetch("SELECT device_id FROM activations WHERE key_id = $1 AND is_active = true", key_id)
            
            # Отправляем уведомление каждому устройству
            for device_row in devices:
                device_id = device_row['device_id']
                
                # Очищаем кеш для этого устройства
                cache_key = f"{key_value}:{device_id}"
                if cache_key in INFO_CACHE:
                    del INFO_CACHE[cache_key]
                    logger.info(f"Cache cleared for {cache_key}")
                
                # Сохраняем уведомление в БД
                await conn.execute("""
                    INSERT INTO device_notifications (device_id, title, body, data)
                    VALUES ($1, $2, $3, $4)
                """, device_id, "⚠️ Ключ удален", "Ваш ключ был удален администратором. Доступ будет сброшен.", json.dumps({"type": "key_revoked", "key": key_value}))
                
                # Отправляем через WebSocket если онлайн
                await manager.send_to_device(device_id, {
                    "type": "key_revoked",
                    "key": key_value,
                    "message": "Your key has been revoked by administrator"
                })
            
            # Деактивируем все активации
            await conn.execute("UPDATE activations SET is_active = false WHERE key_id = $1", key_id)
        
        # Удаляем ключ
        await conn.execute("DELETE FROM keys WHERE id = $1", key_id)
        
        # Очищаем весь кеш связанный с этим ключом
        keys_to_remove = [k for k in INFO_CACHE.keys() if k.startswith(f"{key_value}:")]
        for k in keys_to_remove:
            del INFO_CACHE[k]
            logger.info(f"Cache cleared for {k}")
        
        client_ip = request.client.host if request else "unknown"
        await log_action(current_admin["id"], "delete_key", f"Deleted key: {key_value} (force={force})", client_ip)
        
        return {"message": "Key deleted successfully"}
    finally:
        await conn.close()

# ============================================================
# API - АКТИВАЦИЯ
# ============================================================

@app.post("/api/activate")
async def activate_key(activation: ActivationRequest, request: Request):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        key_row = await conn.fetchrow("""
            SELECT id, key_value, type, duration, max_devices, max_percent, status
            FROM keys
            WHERE key_value = $1
        """, activation.key_code)
        
        if not key_row:
            raise HTTPException(status_code=404, detail="Key not found")
        
        key_id = key_row['id']
        key_status = key_row['status']
        
        if key_status != 'active' and key_status != 'waiting':
            raise HTTPException(status_code=400, detail="Key is not active")
        
        active_count = await conn.fetchval(
            "SELECT COUNT(*) FROM activations WHERE key_id = $1 AND is_active = true",
            key_id
        )
        
        if active_count >= key_row['max_devices']:
            raise HTTPException(status_code=400, detail="Device limit reached")
        
        existing = await conn.fetchrow(
            "SELECT id, is_active FROM activations WHERE key_id = $1 AND device_id = $2",
            key_id, activation.device_id
        )
        
        if existing and existing['is_active']:
            return {"message": "Device already activated", "device_id": activation.device_id}
        
        if key_row['type'] == 'DAY':
            expires_at = datetime.now() + timedelta(days=key_row['duration'])
        else:
            expires_at = datetime.now() + timedelta(hours=key_row['duration'])
        
        if existing:
            await conn.execute("""
                UPDATE activations 
                SET is_active = true, activated_at = CURRENT_TIMESTAMP, expires_at = $1
                WHERE id = $2
            """, expires_at.isoformat(), existing['id'])
        else:
            await conn.execute("""
                INSERT INTO activations (key_id, device_id, expires_at)
                VALUES ($1, $2, $3)
            """, key_id, activation.device_id, expires_at.isoformat())
        
        await conn.execute("""
            UPDATE keys 
            SET used_devices = used_devices + 1,
                first_activation = COALESCE(first_activation, CURRENT_TIMESTAMP),
                status = 'active'
            WHERE id = $1
        """, key_id)
        
        return {
            "message": "Key activated successfully",
            "device_id": activation.device_id,
            "expires_at": expires_at.isoformat(),
            "percent": key_row['max_percent']
        }
    finally:
        await conn.close()

@app.get("/api/check/{key_code}/{device_id}")
async def check_key(key_code: str, device_id: str):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        result = await conn.fetchrow("""
            SELECT k.max_percent, a.expires_at, a.is_active
            FROM keys k
            JOIN activations a ON k.id = a.key_id
            WHERE k.key_value = $1 AND a.device_id = $2
        """, key_code, device_id)
        
        if not result:
            return {"valid": False, "message": "Key not found or not activated for this device"}
        
        if not result['is_active']:
            return {"valid": False, "message": "Activation is inactive"}
        
        expires_at = result['expires_at']
        if isinstance(expires_at, str):
            expires_dt = datetime.fromisoformat(expires_at.replace(' ', 'T'))
        else:
            expires_dt = expires_at
        
        if expires_dt < datetime.now():
            await conn.execute("""
                UPDATE activations SET is_active = false 
                WHERE device_id = $1 AND key_id IN (
                    SELECT id FROM keys WHERE key_value = $2
                )
            """, device_id, key_code)
            return {"valid": False, "message": "Key expired"}
        
        hours_remaining = (expires_dt - datetime.now()).total_seconds() / 3600
        
        return {
            "valid": True,
            "percent": result['max_percent'],
            "expires_at": expires_dt.isoformat(),
            "hours_remaining": round(hours_remaining, 2),
            "device_id": device_id
        }
    finally:
        await conn.close()

# ============================================================
# API - INFOKEY (С КЕШИРОВАНИЕМ)
# ============================================================

@app.get("/api/infokey/{key_code}/{device_id}")
async def get_key_info(key_code: str, device_id: str):
    global CACHE_HITS, CACHE_MISSES
    
    cache_key = f"{key_code}:{device_id}"
    
    # Проверяем кеш
    if cache_key in INFO_CACHE:
        CACHE_HITS += 1
        cached_result = INFO_CACHE[cache_key]
        if cached_result.get('valid') and cached_result.get('hours_remaining', 0) > 0:
            logger.debug(f"Cache hit for {cache_key}")
            return cached_result
    
    CACHE_MISSES += 1
    
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        result = await conn.fetchrow("""
            SELECT k.id, k.max_percent, k.status, a.expires_at, a.is_active
            FROM keys k
            LEFT JOIN activations a ON k.id = a.key_id AND a.device_id = $1
            WHERE k.key_value = $2 AND k.is_active = true
        """, device_id, key_code)
        
        if not result:
            response = {
                "valid": False,
                "message": "Key not found",
                "percent": 0,
                "hours_remaining": 0,
                "expires_at": None
            }
            INFO_CACHE[cache_key] = response
            return response
        
        max_percent = result['max_percent']
        key_status = result['status']
        expires_at = result['expires_at']
        is_active = result['is_active']
        
        if key_status != 'active':
            response = {
                "valid": False,
                "message": "Key not active",
                "percent": max_percent,
                "hours_remaining": 0,
                "expires_at": expires_at
            }
            INFO_CACHE[cache_key] = response
            return response
        
        if not is_active:
            response = {
                "valid": False,
                "message": "Activation inactive",
                "percent": max_percent,
                "hours_remaining": 0,
                "expires_at": expires_at
            }
            INFO_CACHE[cache_key] = response
            return response
        
        if isinstance(expires_at, str):
            expires_dt = datetime.fromisoformat(expires_at.replace(' ', 'T'))
        else:
            expires_dt = expires_at
        
        if expires_dt < datetime.now():
            await conn.execute("""
                UPDATE activations SET is_active = false 
                WHERE key_id = $1 AND device_id = $2
            """, result['id'], device_id)
            
            await conn.execute("""
                UPDATE keys SET status = 'expired' 
                WHERE id = $1 AND NOT EXISTS (
                    SELECT 1 FROM activations 
                    WHERE key_id = keys.id AND is_active = true
                )
            """, result['id'])
            
            response = {
                "valid": False,
                "message": "Activation expired",
                "percent": max_percent,
                "hours_remaining": 0,
                "expires_at": expires_at
            }
            INFO_CACHE[cache_key] = response
            return response
        
        hours_remaining = (expires_dt - datetime.now()).total_seconds() / 3600
        
        response = {
            "valid": True,
            "message": "Key is valid",
            "percent": max_percent,
            "hours_remaining": round(hours_remaining, 2),
            "expires_at": expires_dt.isoformat(),
            "device_id": device_id,
            "key_status": key_status
        }
        
        if response['valid'] and response['hours_remaining'] > 0.1:
            INFO_CACHE[cache_key] = response
        
        return response
    finally:
        await conn.close()

# ============================================================
# API - НАСТРОЙКИ
# ============================================================

@app.get("/api/settings")
async def get_settings():
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        rows = await conn.fetch("SELECT key, value FROM settings")
        settings = {row['key']: row['value'] for row in rows}
        return settings
    finally:
        await conn.close()

@app.post("/api/settings")
async def update_settings(
    settings_data: dict,
    current_admin: dict = Depends(get_current_admin),
    request: Request = None
):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        for key, value in settings_data.items():
            await conn.execute("""
                INSERT INTO settings (key, value, updated_at) 
                VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            """, key, value)
        
        client_ip = request.client.host if request else "unknown"
        await log_action(current_admin["id"], "update_settings", f"Updated settings: {list(settings_data.keys())}", client_ip)
        
        return {"message": "Settings updated successfully"}
    finally:
        await conn.close()

# ============================================================
# API - УВЕДОМЛЕНИЯ (АДМИНСКИЕ)
# ============================================================

@app.get("/api/notifications")
async def get_notifications(current_admin: dict = Depends(get_current_admin)):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        rows = await conn.fetch("SELECT id, text, created_at FROM notifications ORDER BY created_at DESC LIMIT 50")
        return {"notifications": [{"id": row['id'], "text": row['text'], "created_at": row['created_at']} for row in rows]}
    finally:
        await conn.close()

@app.post("/api/notifications")
async def create_notification(notif_data: NotificationCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow(
            "INSERT INTO notifications (text) VALUES ($1) RETURNING id",
            notif_data.text
        )
        
        client_ip = request.client.host if request else "unknown"
        await log_action(current_admin["id"], "create_notification", f"Created notification: {notif_data.text[:50]}...", client_ip)
        
        await manager.broadcast_to_devices({
            "type": "admin_notification",
            "text": notif_data.text,
            "created_at": datetime.now().isoformat()
        })
        
        return {"message": "Notification created", "id": row['id']}
    finally:
        await conn.close()

# ============================================================
# API - УВЕДОМЛЕНИЯ ДЛЯ УСТРОЙСТВ
# ============================================================

@app.post("/api/devices/register")
async def register_device(device_data: DeviceRegister, request: Request):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        existing = await conn.fetchval("SELECT id FROM devices WHERE device_id = $1", device_data.device_id)
        
        if existing:
            await conn.execute("""
                UPDATE devices 
                SET platform = $1, push_token = $2, last_active = CURRENT_TIMESTAMP, is_active = true
                WHERE device_id = $3
            """, device_data.platform, device_data.push_token, device_data.device_id)
        else:
            await conn.execute("""
                INSERT INTO devices (device_id, platform, push_token)
                VALUES ($1, $2, $3)
            """, device_data.device_id, device_data.platform, device_data.push_token)
        
        return {
            "success": True,
            "message": "Device registered successfully",
            "device_id": device_data.device_id
        }
    finally:
        await conn.close()

@app.post("/api/devices/unregister")
async def unregister_device(device_data: DeviceRegister):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        await conn.execute("UPDATE devices SET is_active = false WHERE device_id = $1", device_data.device_id)
        return {"success": True, "message": "Device unregistered"}
    finally:
        await conn.close()

@app.get("/api/devices")
async def get_devices(current_admin: dict = Depends(get_current_admin)):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        rows = await conn.fetch("""
            SELECT device_id, platform, push_token, is_active, last_active, created_at
            FROM devices
            ORDER BY created_at DESC
        """)
        
        devices = []
        for row in rows:
            devices.append({
                "device_id": row['device_id'],
                "platform": row['platform'],
                "has_push_token": bool(row['push_token']),
                "is_active": bool(row['is_active']),
                "last_active": row['last_active'],
                "registered_at": row['created_at']
            })
        
        return {"devices": devices}
    finally:
        await conn.close()

@app.post("/api/notifications/send")
async def send_device_notification(
    notification: DeviceNotification,
    current_admin: dict = Depends(get_current_admin),
    request: Request = None
):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow(
            "SELECT platform, push_token FROM devices WHERE device_id = $1 AND is_active = true",
            notification.device_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="Device not found or inactive")
        
        await conn.execute("""
            INSERT INTO device_notifications (device_id, title, body, data)
            VALUES ($1, $2, $3, $4)
        """, notification.device_id, notification.title, notification.body, json.dumps(notification.data) if notification.data else None)
        
        sent = await manager.send_to_device(notification.device_id, {
            "type": "notification",
            "title": notification.title,
            "body": notification.body,
            "data": notification.data
        })
        
        client_ip = request.client.host if request else "unknown"
        await log_action(
            current_admin["id"], 
            "send_device_notification", 
            f"To {notification.device_id}: {notification.title}",
            client_ip
        )
        
        return {
            "success": True,
            "message": "Notification sent",
            "device_id": notification.device_id,
            "delivered": sent
        }
    finally:
        await conn.close()

@app.post("/api/notifications/broadcast")
async def broadcast_notification(
    broadcast: BroadcastNotification,
    current_admin: dict = Depends(get_current_admin),
    request: Request = None
):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        query = "SELECT device_id, push_token FROM devices WHERE is_active = true"
        params = []
        if broadcast.platform:
            query += " AND platform = $1"
            params.append(broadcast.platform)
        
        rows = await conn.fetch(query, *params)
        
        saved_count = 0
        for row in rows:
            await conn.execute("""
                INSERT INTO device_notifications (device_id, title, body, data, is_delivered)
                VALUES ($1, $2, $3, $4, false)
            """, row['device_id'], broadcast.title, broadcast.body, json.dumps(broadcast.data) if broadcast.data else None)
            saved_count += 1
        
        sent = await manager.broadcast_to_devices({
            "type": "notification",
            "title": broadcast.title,
            "body": broadcast.body,
            "data": broadcast.data
        }, broadcast.platform)
        
        client_ip = request.client.host if request else "unknown"
        await log_action(
            current_admin["id"], 
            "broadcast_notification", 
            f"Broadcast: {broadcast.title} to {saved_count} devices (WS: {sent})",
            client_ip
        )
        
        return {
            "success": True,
            "message": f"Broadcast sent to {saved_count} devices",
            "total_devices": saved_count,
            "websocket_delivered": sent
        }
    finally:
        await conn.close()

@app.get("/api/notifications/device/{device_id}")
async def get_device_notifications(
    device_id: str,
    limit: int = 50,
    unread_only: bool = False
):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        query = """
            SELECT id, title, body, data, is_read, created_at
            FROM device_notifications
            WHERE device_id = $1
        """
        params = [device_id]
        
        if unread_only:
            query += " AND is_read = false"
        
        query += " ORDER BY created_at DESC LIMIT $2"
        params.append(min(limit, 100))
        
        rows = await conn.fetch(query, *params)
        
        notifications = []
        for row in rows:
            notifications.append({
                "id": row['id'],
                "title": row['title'],
                "body": row['body'],
                "data": json.loads(row['data']) if row['data'] else None,
                "is_read": bool(row['is_read']),
                "created_at": row['created_at']
            })
        
        return {"notifications": notifications, "total": len(notifications)}
    finally:
        await conn.close()

@app.post("/api/notifications/device/{device_id}/read/{notification_id}")
async def mark_notification_read(device_id: str, notification_id: int):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        result = await conn.execute(
            "UPDATE device_notifications SET is_read = true WHERE id = $1 AND device_id = $2",
            notification_id, device_id
        )
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Notification not found")
        return {"success": True, "message": "Marked as read"}
    finally:
        await conn.close()

@app.post("/api/notifications/device/{device_id}/read-all")
async def mark_all_read(device_id: str):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        result = await conn.execute(
            "UPDATE device_notifications SET is_read = true WHERE device_id = $1 AND is_read = false",
            device_id
        )
        return {"success": True, "read_count": int(result.split()[-1])}
    finally:
        await conn.close()

# ============================================================
# API - РЕКЛАМА
# ============================================================

@app.get("/api/ads")
async def get_ads():
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow("""
            SELECT html, is_closable 
            FROM advertisements 
            WHERE is_active = true 
            ORDER BY updated_at DESC 
            LIMIT 1
        """)
        if row:
            return {"html": row['html'], "is_closable": bool(row['is_closable'])}
        return {"html": "", "is_closable": True}
    finally:
        await conn.close()

@app.post("/api/ads")
async def save_ads(ad_data: AdCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        await conn.execute("UPDATE advertisements SET is_active = false WHERE is_active = true")
        await conn.execute(
            "INSERT INTO advertisements (html, is_closable, is_active) VALUES ($1, $2, true)",
            ad_data.html, ad_data.is_closable
        )
        
        client_ip = request.client.host if request else "unknown"
        await log_action(current_admin["id"], "update_ad", "Updated advertisement", client_ip)
        
        return {"message": "Advertisement saved"}
    finally:
        await conn.close()

# ============================================================
# API - ОБНОВЛЕНИЯ
# ============================================================

@app.post("/api/check-update")
async def check_update(request: CheckUpdateRequest):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow("""
            SELECT version, download_url, changelog, is_forced
            FROM updates
            WHERE platform = $1
            ORDER BY created_at DESC
            LIMIT 1
        """, request.platform)
        
        if not row:
            return {"has_update": False}
        
        if row['version'] > request.current_version:
            return {
                "has_update": True,
                "version": row['version'],
                "download_url": row['download_url'],
                "changelog": row['changelog'],
                "is_forced": bool(row['is_forced'])
            }
        
        return {"has_update": False}
    finally:
        await conn.close()

# ============================================================
# API - ЛОГИ
# ============================================================

@app.get("/api/logs")
async def get_logs(
    skip: int = 0, 
    limit: int = 100, 
    current_admin: dict = Depends(get_current_admin)
):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        rows = await conn.fetch("""
            SELECT l.*, a.username
            FROM logs l
            LEFT JOIN admins a ON l.admin_id = a.id
            ORDER BY l.created_at DESC
            LIMIT $1 OFFSET $2
        """, min(limit, MAX_LIMIT), skip)
        
        logs = []
        for row in rows:
            logs.append({
                "id": row['id'],
                "admin_id": row['admin_id'],
                "admin": row['username'] if row.get('username') else "System",
                "action": row['action'],
                "details": row['details'],
                "ip": row['ip_address'],
                "created_at": row['created_at']
            })
        
        total = await conn.fetchval("SELECT COUNT(*) FROM logs")
        
        return {"items": logs, "total": total or 0, "skip": skip, "limit": limit}
    finally:
        await conn.close()

# ============================================================
# API - CACHE STATS
# ============================================================

@app.get("/api/cache-stats")
async def get_cache_stats(current_admin: dict = Depends(get_current_admin)):
    global CACHE_HITS, CACHE_MISSES
    
    total = CACHE_HITS + CACHE_MISSES
    hit_rate = (CACHE_HITS / total * 100) if total > 0 else 0
    
    return {
        "cache_size": len(INFO_CACHE),
        "max_size": INFO_CACHE.maxsize,
        "ttl_seconds": INFO_CACHE.ttl,
        "hits": CACHE_HITS,
        "misses": CACHE_MISSES,
        "total_requests": total,
        "hit_rate": round(hit_rate, 2)
    }

# ============================================================
# API - WS STATUS
# ============================================================

@app.get("/api/devices/ws-status/{device_id}")
async def get_ws_status(device_id: str, current_admin: dict = Depends(get_current_admin)):
    is_connected = device_id in manager.active_connections
    
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow(
            "SELECT platform, is_active, last_active FROM devices WHERE device_id = $1",
            device_id
        )
        
        if not row:
            return {"connected": False, "exists": False}
        
        return {
            "connected": is_connected,
            "exists": True,
            "platform": row['platform'],
            "is_active": bool(row['is_active']),
            "last_active": row['last_active']
        }
    finally:
        await conn.close()

# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket("/ws/device/{device_id}")
async def websocket_device(websocket: WebSocket, device_id: str):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        # Автоматическая регистрация
        row = await conn.fetchrow("SELECT id FROM devices WHERE device_id = $1", device_id)
        if not row:
            await conn.execute("""
                INSERT INTO devices (device_id, platform, is_active)
                VALUES ($1, 'android', true)
            """, device_id)
            logger.info(f"Auto-registered device via WebSocket: {device_id}")
        else:
            await conn.execute("""
                UPDATE devices 
                SET is_active = true, last_active = CURRENT_TIMESTAMP
                WHERE device_id = $1
            """, device_id)
    finally:
        await conn.close()
    
    await manager.connect_device(device_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get('type') == 'ping':
                    await websocket.send_json({'type': 'pong'})
            except:
                pass
    except WebSocketDisconnect:
        manager.disconnect_device(device_id)
    except Exception as e:
        logger.error(f"WebSocket error for device {device_id}: {e}")
        manager.disconnect_device(device_id)

@app.websocket("/ws/admin/{admin_id}")
async def websocket_admin(websocket: WebSocket, admin_id: int):
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql://", "postgresql://"))
    try:
        row = await conn.fetchrow("SELECT id FROM admins WHERE id = $1 AND is_active = true", admin_id)
        if not row:
            await websocket.close(code=1008, reason="Admin not found")
            return
    finally:
        await conn.close()
    
    await manager.connect_admin(admin_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_admin(admin_id)
    except Exception as e:
        logger.error(f"WebSocket error for admin {admin_id}: {e}")
        manager.disconnect_admin(admin_id)

# ============================================================
# ОБРАБОТКА ОШИБОК
# ============================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# ============================================================
# ЗАПУСК
# ============================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
  )
