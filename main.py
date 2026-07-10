import os
import sys
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request
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
import aiosqlite

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

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
DATABASE_PATH = os.getenv("DATABASE_PATH", "orangmods.db")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")
MAX_LIMIT = int(os.getenv("MAX_LIMIT", "100"))

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

# ============================================================
# LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_database_async()
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
    
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("SELECT id, username FROM admins WHERE id = ? AND is_active = 1", (admin_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Admin not found")
        return {"id": row[0], "username": row[1]}

# ============================================================
# РАБОТА С БД
# ============================================================

@asynccontextmanager
async def get_db_async():
    conn = await aiosqlite.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")
        yield conn
        await conn.commit()
    except Exception as e:
        await conn.rollback()
        logger.error(f"Database error: {e}")
        raise e
    finally:
        await conn.close()

@contextmanager
def get_db_sync():
    conn = sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False,
        timeout=30
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise e
    finally:
        conn.close()

async def init_database_async():
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        
        # Таблица администраторов
        await cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username)")
        
        # Таблица ключей
        await cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('DAY', 'HOUR')),
                duration INTEGER NOT NULL,
                max_devices INTEGER NOT NULL,
                max_percent INTEGER NOT NULL,
                used_devices INTEGER DEFAULT 0,
                first_activation TIMESTAMP,
                status TEXT DEFAULT 'waiting',
                is_active INTEGER DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES admins(id)
            )
        """)
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys(key_value)")
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)")
        
        # Таблица активаций
        await cursor.execute("""
            CREATE TABLE IF NOT EXISTS activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (key_id) REFERENCES keys(id),
                UNIQUE(key_id, device_id)
            )
        """)
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_activations_key_id ON activations(key_id)")
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_activations_device_id ON activations(device_id)")
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_activations_expires_at ON activations(expires_at)")
        
        # Таблица уведомлений
        await cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)")
        
        # Таблица рекламы
        await cursor.execute("""
            CREATE TABLE IF NOT EXISTS advertisements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                html TEXT NOT NULL,
                is_closable INTEGER DEFAULT 1,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Таблица логов
        await cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id)
            )
        """)
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at)")
        
        # Таблица обновлений
        await cursor.execute("""
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL CHECK(platform IN ('android', 'ios', 'windows')),
                download_url TEXT NOT NULL,
                changelog TEXT,
                is_forced INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await cursor.execute("CREATE INDEX IF NOT EXISTS idx_updates_platform ON updates(platform)")
        
        # Создание админа
        await cursor.execute("SELECT COUNT(*) FROM admins")
        row = await cursor.fetchone()
        if row and row[0] == 0:
            hashed = get_password_hash(DEFAULT_ADMIN_PASSWORD)
            await cursor.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                (DEFAULT_ADMIN_USERNAME, hashed)
            )
            logger.info(f"Created default admin user: {DEFAULT_ADMIN_USERNAME}")
        
        # Получаем ID админа
        await cursor.execute("SELECT id FROM admins WHERE username = ?", (DEFAULT_ADMIN_USERNAME,))
        admin_row = await cursor.fetchone()
        admin_id = admin_row[0] if admin_row else 1
        
        # Создание тестовых ключей
        await cursor.execute("SELECT COUNT(*) FROM keys")
        row = await cursor.fetchone()
        if row and row[0] == 0:
            test_keys = [
                ("OrangMods-7DAY-XYZ123", "Тестовый ключ 1", "DAY", 7, 5, 70, "active"),
                ("OrangMods-30DAY-ABC456", "Тестовый ключ 2", "DAY", 30, 10, 80, "waiting"),
                ("OrangMods-12HOUR-DEF789", "Тестовый ключ 3", "HOUR", 12, 3, 90, "expired"),
                ("OrangMods-1DAY-6XGXQRDJ5Y", "Тестовый ключ 4", "DAY", 1, 3, 80, "waiting"),
            ]
            for key in test_keys:
                await cursor.execute("""
                    INSERT INTO keys (key_value, name, type, duration, max_devices, max_percent, status, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (*key, admin_id))
            logger.info("Created test keys")

# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

def generate_key_code(key_type: str, duration: int) -> str:
    type_map = {"DAY": f"{duration}DAY", "HOUR": f"{duration}HOUR"}
    type_str = type_map.get(key_type, "DAY")
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    random_part = ''.join(secrets.choice(chars) for _ in range(10))
    return f"OrangMods-{type_str}-{random_part}"

def log_action(admin_id: int, action: str, details: str = None, ip: str = None):
    try:
        with get_db_sync() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
                (admin_id, action, details, ip)
            )
    except Exception as e:
        logger.error(f"Error logging action: {e}")

def calculate_time_left(key: dict) -> dict:
    if key.get('status') != 'active' or not key.get('first_activation'):
        return {'time_left': 'НЕТ', 'time_left_seconds': 0}
    
    try:
        first_act_str = key['first_activation']
        try:
            first_act = datetime.fromisoformat(first_act_str.replace(' ', 'T'))
        except ValueError:
            first_act = datetime.strptime(first_act_str, "%Y-%m-%d %H:%M:%S")
        
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

def format_key_row(row) -> dict:
    key_dict = {
        "id": row[0],
        "key_value": row[1],
        "name": row[2],
        "type": row[3],
        "duration": row[4],
        "max_devices": row[5],
        "max_percent": row[6],
        "used_devices": row[7],
        "first_activation": row[8],
        "status": row[9],
        "created_at": row[10]
    }
    time_info = calculate_time_left(key_dict)
    key_dict.update(time_info)
    return key_dict

def cleanup_expired_activations():
    try:
        with get_db_sync() as conn:
            cursor = conn.cursor()
            # Обновляем статусы ключей
            cursor.execute("""
                UPDATE keys 
                SET status = 'expired' 
                WHERE status = 'active' 
                AND datetime(
                    first_activation, 
                    '+' || duration || ' ' || 
                    CASE WHEN type = 'DAY' THEN 'days' ELSE 'hours' END
                ) < datetime('now')
            """)
            updated = cursor.rowcount
            if updated > 0:
                logger.info(f"Cleaned up {updated} expired keys")
            
            # Деактивируем просроченные активации
            cursor.execute("""
                UPDATE activations 
                SET is_active = 0 
                WHERE is_active = 1 AND expires_at < datetime('now')
            """)
            deactivated = cursor.rowcount
            if deactivated > 0:
                logger.info(f"Deactivated {deactivated} expired activations")
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
        /* ===== RESET & BASE ===== */
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

        /* ===== HEADER ===== */
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

        /* ===== TOASTS ===== */
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

        /* ===== LOGIN ===== */
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

        .field input::placeholder,
        .field textarea::placeholder {
            color: #555;
        }

        /* ===== BUTTONS ===== */
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

        /* ===== LOADING ===== */
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

        /* ===== STATUS MESSAGES ===== */
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

        /* ===== ADMIN CONTENT ===== */
        .admin-content {
            display: none;
        }

        .admin-content.active {
            display: block;
            animation: fadeUp 0.5s ease;
        }

        /* ===== ADMIN HEADER ===== */
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

        /* ===== TABS ===== */
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

        /* ===== CARDS ===== */
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

        /* ===== TABLE ===== */
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

        /* ===== STATUS BADGES ===== */
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

        /* ===== KEY DISPLAY ===== */
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

        /* ===== TABLE CONTROLS ===== */
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

        /* ===== SEARCH ===== */
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

        /* ===== EXPORT ===== */
        .export-buttons {
            display: flex;
            gap: 8px;
        }

        .export-buttons .btn-sm {
            padding: 6px 14px;
            font-size: 9px;
            letter-spacing: 0.5px;
        }

        /* ===== PERCENT SLIDER ===== */
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

        /* ===== BULK ACTIONS ===== */
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

        /* ===== TIMER ===== */
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

        /* ===== EMPTY STATE ===== */
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

        /* ===== CHECKBOX ===== */
        input[type="checkbox"] {
            accent-color: #ff8c00;
            width: 16px;
            height: 16px;
            cursor: pointer;
        }

        /* ===== AD PREVIEW ===== */
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

        /* ===== NOTIFICATION HISTORY ===== */
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

        /* ===== RESPONSIVE ===== */
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

        /* ===== SCROLLBAR ===== */
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

        /* ===== MISC ===== */
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

    <!-- ===== TOAST CONTAINER ===== -->
    <div class="toast-container" id="toastContainer"></div>

    <div class="container">

        <!-- ===== LOGO ===== -->
        <div class="logo-section">
            <div class="logo">ORANGMODS</div>
            <div class="logo-sub">Admin Panel · Control Center</div>
        </div>
        <div class="divider"></div>

        <!-- ===== LOGIN FORM ===== -->
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

        <!-- ===== ADMIN PANEL ===== -->
        <div class="admin-content" id="adminContent">

            <!-- Admin Header -->
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

            <!-- Tabs -->
            <div class="tabs">
                <button class="tab active" data-tab="tab1">📋 Ключи</button>
                <button class="tab" data-tab="tab2">➕ Создать</button>
                <button class="tab" data-tab="tab3">📢 Уведомления</button>
                <button class="tab" data-tab="tab4">🎯 Реклама</button>
            </div>

            <!-- ===== TAB 1: KEYS ===== -->
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

            <!-- ===== TAB 2: CREATE KEY ===== -->
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

            <!-- ===== TAB 3: NOTIFICATIONS ===== -->
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

            <!-- ===== TAB 4: ADVERTISEMENT ===== -->
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

            // ============================================================
            // 1. API CLASS
            // ============================================================
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

            // ============================================================
            // 2. GLOBALS
            // ============================================================
            const api = new Api();

            // DOM refs
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

            // Cache
            let cache = {
                keys: [],
                notifications: [],
                ads: { html: '', is_closable: true },
                stats: {}
            };

            let selectedActiveSet = new Set();
            let selectedExpiredSet = new Set();

            // ============================================================
            // 3. TOASTS
            // ============================================================
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

            // ============================================================
            // 4. RENDER FUNCTIONS
            // ============================================================
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

                // Copy buttons
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

                // Checkboxes
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

            // ============================================================
            // 5. DATA LOADING
            // ============================================================
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
                        // handled in callback
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

            // ============================================================
            // 6. AUTH
            // ============================================================
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

            // ============================================================
            // 7. EXPORT
            // ============================================================
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

            // ============================================================
            // 8. EVENT LISTENERS
            // ============================================================
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

            // ============================================================
            // 9. TABS
            // ============================================================
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

            // ============================================================
            // 10. INIT
            // ============================================================
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
# API МАРШРУТЫ - АДМИНКА
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def serve_admin():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
async def health_check():
    try:
        async with get_db_async() as conn:
            cursor = await conn.cursor()
            await cursor.execute("SELECT 1")
            await cursor.fetchone()
        return {"status": "ok", "timestamp": datetime.now().isoformat()}
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
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute(
            "SELECT id, username, password_hash FROM admins WHERE username = ? AND is_active = 1",
            (login_data.login,)
        )
        row = await cursor.fetchone()
        if not row or not verify_password(login_data.password, row[2]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"sub": str(row[0]), "username": row[1]})
        
        client_ip = request.client.host if request.client else "unknown"
        log_action(row[0], "login", f"Login from {client_ip}", client_ip)
        
        return {"success": True, "token": token, "username": row[1]}

# ============================================================
# API МАРШРУТЫ - ДАШБОРД
# ============================================================

@app.get("/api/dashboard")
async def get_dashboard(current_admin: dict = Depends(get_current_admin)):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        
        # Статистика
        await cursor.execute("SELECT COUNT(*) FROM keys")
        row = await cursor.fetchone()
        total_keys = row[0] if row else 0
        
        await cursor.execute("SELECT COUNT(*) FROM keys WHERE status = 'active'")
        row = await cursor.fetchone()
        active_keys = row[0] if row else 0
        
        await cursor.execute("SELECT COUNT(*) FROM keys WHERE status = 'expired'")
        row = await cursor.fetchone()
        expired_keys = row[0] if row else 0
        
        await cursor.execute("SELECT SUM(used_devices) FROM keys")
        row = await cursor.fetchone()
        total_devices = row[0] if row and row[0] else 0
        
        stats = {
            "total_keys": total_keys,
            "active_keys": active_keys,
            "expired_keys": expired_keys,
            "total_devices": total_devices
        }
        
        # Ключи
        await cursor.execute("""
            SELECT id, key_value, name, type, duration, max_devices, max_percent, 
                   used_devices, first_activation, status, created_at
            FROM keys
            ORDER BY created_at DESC
        """)
        rows = await cursor.fetchall()
        keys_list = [format_key_row(row) for row in rows]
        
        # Уведомления
        await cursor.execute("SELECT id, text, created_at FROM notifications ORDER BY created_at DESC LIMIT 50")
        rows = await cursor.fetchall()
        notifications = [{"id": row[0], "text": row[1], "created_at": row[2]} for row in rows]
        
        # Реклама
        await cursor.execute("SELECT html, is_closable FROM advertisements WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1")
        row = await cursor.fetchone()
        ads = {"html": row[0] if row else "", "is_closable": bool(row[1]) if row and row[1] else True}
        
        # Логи (последние 10)
        await cursor.execute("""
            SELECT l.*, a.username 
            FROM logs l 
            LEFT JOIN admins a ON l.admin_id = a.id 
            ORDER BY l.created_at DESC LIMIT 10
        """)
        logs = []
        async for log_row in cursor:
            logs.append({
                "id": log_row[0],
                "admin": log_row[6] if len(log_row) > 6 else "System",
                "action": log_row[2],
                "details": log_row[3],
                "created_at": log_row[5]
            })
        
        return {
            "stats": stats,
            "keys": keys_list,
            "notifications": notifications,
            "ads": ads,
            "logs": logs
        }

# ============================================================
# API МАРШРУТЫ - КЛЮЧИ
# ============================================================

@app.get("/api/keys")
async def get_keys(current_admin: dict = Depends(get_current_admin)):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("""
            SELECT id, key_value, name, type, duration, max_devices, max_percent, 
                   used_devices, first_activation, status, created_at
            FROM keys
            ORDER BY created_at DESC
            LIMIT ?
        """, (MAX_LIMIT,))
        
        rows = await cursor.fetchall()
        keys_list = [format_key_row(row) for row in rows]
        
        return {"keys": keys_list}

@app.post("/api/keys")
async def create_key(key_data: KeyCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    key_value = generate_key_code(key_data.type, key_data.duration)
    
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("""
            INSERT INTO keys (key_value, name, type, duration, max_devices, max_percent, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?)
        """, (key_value, key_data.name, key_data.type, key_data.duration, key_data.max_devices, key_data.max_percent, current_admin["id"]))
        
        await cursor.execute("SELECT last_insert_rowid()")
        row = await cursor.fetchone()
        key_id = row[0] if row else None
        
        client_ip = request.client.host if request else "unknown"
        log_action(current_admin["id"], "create_key", f"Created key: {key_value}", client_ip)
        
        return {
            "id": key_id,
            "key_value": key_value,
            "name": key_data.name,
            "type": key_data.type,
            "duration": key_data.duration,
            "max_devices": key_data.max_devices,
            "max_percent": key_data.max_percent,
            "status": "waiting"
        }

@app.delete("/api/keys/{key_id}")
async def delete_key(key_id: int, current_admin: dict = Depends(get_current_admin), request: Request = None):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("SELECT key_value FROM keys WHERE id = ?", (key_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found")
        
        await cursor.execute("DELETE FROM keys WHERE id = ?", (key_id,))
        
        client_ip = request.client.host if request else "unknown"
        log_action(current_admin["id"], "delete_key", f"Deleted key: {row[0]}", client_ip)
        
        return {"message": "Key deleted successfully"}

# ============================================================
# API МАРШРУТЫ - АКТИВАЦИЯ (ДЛЯ ПРИЛОЖЕНИЯ)
# ============================================================

@app.post("/api/activate")
async def activate_key(activation: ActivationRequest, request: Request):
    """Активация ключа для устройства"""
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        
        # Поиск ключа
        await cursor.execute("""
            SELECT id, key_value, type, duration, max_devices, max_percent, status
            FROM keys
            WHERE key_value = ?
        """, (activation.key_code,))
        key_row = await cursor.fetchone()
        
        if not key_row:
            raise HTTPException(status_code=404, detail="Key not found")
        
        key_id = key_row[0]
        key_status = key_row[6]
        
        if key_status != 'active' and key_status != 'waiting':
            raise HTTPException(status_code=400, detail="Key is not active")
        
        # Проверка лимита устройств
        await cursor.execute(
            "SELECT COUNT(*) FROM activations WHERE key_id = ? AND is_active = 1",
            (key_id,)
        )
        count_row = await cursor.fetchone()
        active_count = count_row[0] if count_row else 0
        
        if active_count >= key_row[4]:
            raise HTTPException(status_code=400, detail="Device limit reached")
        
        # Проверка существующей активации
        await cursor.execute(
            "SELECT id, is_active FROM activations WHERE key_id = ? AND device_id = ?",
            (key_id, activation.device_id)
        )
        existing = await cursor.fetchone()
        
        if existing and existing[1] == 1:
            return {"message": "Device already activated", "device_id": activation.device_id}
        
        # Расчет даты истечения
        if key_row[2] == 'DAY':
            expires_at = datetime.now() + timedelta(days=key_row[3])
        else:
            expires_at = datetime.now() + timedelta(hours=key_row[3])
        
        # Создание активации
        if existing:
            await cursor.execute("""
                UPDATE activations 
                SET is_active = 1, activated_at = CURRENT_TIMESTAMP, expires_at = ?
                WHERE id = ?
            """, (expires_at.isoformat(), existing[0]))
        else:
            await cursor.execute("""
                INSERT INTO activations (key_id, device_id, expires_at)
                VALUES (?, ?, ?)
            """, (key_id, activation.device_id, expires_at.isoformat()))
        
        # Обновление статистики ключа
        await cursor.execute("""
            UPDATE keys 
            SET used_devices = used_devices + 1,
                first_activation = COALESCE(first_activation, CURRENT_TIMESTAMP),
                status = 'active'
            WHERE id = ?
        """, (key_id,))
        
        return {
            "message": "Key activated successfully",
            "device_id": activation.device_id,
            "expires_at": expires_at.isoformat(),
            "percent": key_row[5]
        }

@app.get("/api/check/{key_code}/{device_id}")
async def check_key(key_code: str, device_id: str):
    """Проверка ключа для устройства"""
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        
        # Проверка активации
        await cursor.execute("""
            SELECT k.max_percent, a.expires_at, a.is_active
            FROM keys k
            JOIN activations a ON k.id = a.key_id
            WHERE k.key_value = ? AND a.device_id = ?
        """, (key_code, device_id))
        result = await cursor.fetchone()
        
        if not result:
            return {"valid": False, "message": "Key not found or not activated for this device"}
        
        if result[2] == 0:
            return {"valid": False, "message": "Activation is inactive"}
        
        try:
            expires_at = datetime.fromisoformat(result[1].replace(' ', 'T'))
        except:
            expires_at = datetime.strptime(result[1], "%Y-%m-%d %H:%M:%S")
        
        if expires_at < datetime.now():
            # Деактивируем просроченную активацию
            await cursor.execute("""
                UPDATE activations SET is_active = 0 WHERE device_id = ? AND key_id IN (
                    SELECT id FROM keys WHERE key_value = ?
                )
            """, (device_id, key_code))
            return {"valid": False, "message": "Key expired"}
        
        hours_remaining = (expires_at - datetime.now()).total_seconds() / 3600
        
        return {
            "valid": True,
            "percent": result[0],
            "expires_at": expires_at.isoformat(),
            "hours_remaining": round(hours_remaining, 2),
            "device_id": device_id
        }

# ============================================================
# API МАРШРУТЫ - УВЕДОМЛЕНИЯ
# ============================================================

@app.get("/api/notifications")
async def get_notifications(current_admin: dict = Depends(get_current_admin)):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("SELECT id, text, created_at FROM notifications ORDER BY created_at DESC LIMIT 50")
        rows = await cursor.fetchall()
        notifications = [{"id": row[0], "text": row[1], "created_at": row[2]} for row in rows]
        return {"notifications": notifications}

@app.get("/api/notifications/latest")
async def get_latest_notifications(limit: int = 10):
    """Получение последних уведомлений для приложения"""
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("""
            SELECT id, text, created_at 
            FROM notifications 
            ORDER BY created_at DESC 
            LIMIT ?
        """, (min(limit, 20),))
        rows = await cursor.fetchall()
        return [{"id": row[0], "text": row[1], "created_at": row[2]} for row in rows]

@app.post("/api/notifications")
async def create_notification(notif_data: NotificationCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute(
            "INSERT INTO notifications (text) VALUES (?)",
            (notif_data.text,)
        )
        
        await cursor.execute("SELECT last_insert_rowid()")
        row = await cursor.fetchone()
        notification_id = row[0] if row else None
        
        client_ip = request.client.host if request else "unknown"
        log_action(current_admin["id"], "create_notification", f"Created notification: {notif_data.text[:50]}...", client_ip)
        
        return {"message": "Notification created", "id": notification_id}

# ============================================================
# API МАРШРУТЫ - РЕКЛАМА
# ============================================================

@app.get("/api/ads")
async def get_ads():
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("""
            SELECT html, is_closable 
            FROM advertisements 
            WHERE is_active = 1 
            ORDER BY updated_at DESC 
            LIMIT 1
        """)
        row = await cursor.fetchone()
        if row:
            return {"html": row[0], "is_closable": bool(row[1])}
        return {"html": "", "is_closable": True}

@app.post("/api/ads")
async def save_ads(ad_data: AdCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("UPDATE advertisements SET is_active = 0 WHERE is_active = 1")
        await cursor.execute(
            "INSERT INTO advertisements (html, is_closable, is_active) VALUES (?, ?, 1)",
            (ad_data.html, 1 if ad_data.is_closable else 0)
        )
        
        client_ip = request.client.host if request else "unknown"
        log_action(current_admin["id"], "update_ad", "Updated advertisement", client_ip)
        
        return {"message": "Advertisement saved"}

# ============================================================
# API МАРШРУТЫ - ОБНОВЛЕНИЯ
# ============================================================

@app.post("/api/check-update")
async def check_update(request: CheckUpdateRequest):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("""
            SELECT version, download_url, changelog, is_forced
            FROM updates
            WHERE platform = ?
            ORDER BY created_at DESC
            LIMIT 1
        """, (request.platform,))
        row = await cursor.fetchone()
        
        if not row:
            return {"has_update": False}
        
        # Простое сравнение версий
        if row[0] > request.current_version:
            return {
                "has_update": True,
                "version": row[0],
                "download_url": row[1],
                "changelog": row[2],
                "is_forced": bool(row[3])
            }
        
        return {"has_update": False}

# ============================================================
# API МАРШРУТЫ - ЛОГИ
# ============================================================

@app.get("/api/logs")
async def get_logs(
    skip: int = 0, 
    limit: int = 100, 
    current_admin: dict = Depends(get_current_admin)
):
    async with get_db_async() as conn:
        cursor = await conn.cursor()
        await cursor.execute("""
            SELECT l.*, a.username
            FROM logs l
            LEFT JOIN admins a ON l.admin_id = a.id
            ORDER BY l.created_at DESC
            LIMIT ? OFFSET ?
        """, (min(limit, MAX_LIMIT), skip))
        rows = await cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "admin_id": row[1],
                "admin": row[6] if len(row) > 6 else "System",
                "action": row[2],
                "details": row[3],
                "ip": row[4],
                "created_at": row[5]
            })
        
        await cursor.execute("SELECT COUNT(*) FROM logs")
        count_row = await cursor.fetchone()
        total = count_row[0] if count_row else 0
        
        return {"items": logs, "total": total, "skip": skip, "limit": limit}

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
