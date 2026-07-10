import os
import sys
import sqlite3
import uuid
import hashlib
import secrets
import string
import json
import re
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from jose import jwt, JWTError, ExpiredSignatureError
from datetime import timezone
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from packaging.version import Version

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Конфигурация
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logger.error("SECRET_KEY environment variable is required!")
    sys.exit(1)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
DATABASE_PATH = os.getenv("DATABASE_PATH", "orangmods.db")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")
MAX_LIMIT = int(os.getenv("MAX_LIMIT", "100"))

# Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
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

# Middleware для логирования ошибок
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

# CORS
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

# Модели данных для API
class AdminLogin(BaseModel):
    login: str
    password: str

class KeyCreate(BaseModel):
    name: str
    type: str
    duration: int
    max_devices: int
    max_percent: int

class NotificationCreate(BaseModel):
    text: str

class AdCreate(BaseModel):
    html: str
    is_closable: bool

class KeyDelete(BaseModel):
    key_value: str

# Безопасность
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
        "iss": "orangmods"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM admins WHERE id = ? AND is_active = 1", (admin_id,))
        admin = cursor.fetchone()
        if not admin:
            raise HTTPException(status_code=401, detail="Admin not found")
        return {"id": admin[0], "username": admin[1]}

# Работа с БД
@contextmanager
def get_db():
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

def init_database():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Таблицы
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username)")
        
        cursor.execute("""
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys(key_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS advertisements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                html TEXT NOT NULL,
                is_closable INTEGER DEFAULT 1,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at)")
        
        # Создание админа
        cursor.execute("SELECT COUNT(*) FROM admins")
        if cursor.fetchone()[0] == 0:
            default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "pa9w9diqllOoeje")
            hashed = get_password_hash(default_password)
            cursor.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                (os.getenv("DEFAULT_ADMIN_USERNAME", "Ad09oLq@Gmail.yandex"), hashed)
            )
            logger.info("Created default admin user")
        
        # Создание тестовых ключей
        cursor.execute("SELECT COUNT(*) FROM keys")
        if cursor.fetchone()[0] == 0:
            test_keys = [
                ("OrangMods-7DAY-XYZ123", "Тестовый ключ 1", "DAY", 7, 5, 70, "active"),
                ("OrangMods-30DAY-ABC456", "Тестовый ключ 2", "DAY", 30, 10, 80, "waiting"),
                ("OrangMods-12HOUR-DEF789", "Тестовый ключ 3", "HOUR", 12, 3, 90, "expired"),
            ]
            for key in test_keys:
                cursor.execute("""
                    INSERT INTO keys (key_value, name, type, duration, max_devices, max_percent, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, key)
            logger.info("Created test keys")

def generate_key_code(key_type: str, duration: int) -> str:
    type_map = {"DAY": f"{duration}DAY", "HOUR": f"{duration}HOUR"}
    type_str = type_map.get(key_type, "DAY")
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    random_part = ''.join(secrets.choice(chars) for _ in range(10))
    return f"OrangMods-{type_str}-{random_part}"

def log_action(admin_id: int, action: str, details: str = None, ip: str = None):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
                (admin_id, action, details, ip)
            )
    except Exception as e:
        logger.error(f"Error logging action: {e}")

def cleanup_expired_activations():
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE keys 
                SET status = 'expired' 
                WHERE status = 'active' 
                AND datetime(first_activation, '+' || duration || ' ' || 
                    CASE WHEN type = 'DAY' THEN 'days' ELSE 'hours' END) < datetime('now')
            """)
            updated = cursor.rowcount
            if updated > 0:
                logger.info(f"Cleaned up {updated} expired keys")
    except Exception as e:
        logger.error(f"Error cleaning up expired keys: {e}")

# Создаем директорию для статических файлов
STATIC_DIR = Path("static")
STATIC_DIR.mkdir(exist_ok=True)

# HTML админка (ваш файл)
ADMIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OrangMods Admin Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Orbitron', sans-serif;
        }

        body {
            min-height: 100vh;
            background: radial-gradient(circle at top, #ff7b00 0, #111 40%, #050505 100%);
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
            background: linear-gradient(rgba(255, 255, 255, .03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, .03) 1px, transparent 1px);
            background-size: 40px 40px;
            animation: grid 12s linear infinite;
            pointer-events: none;
            z-index: 0;
        }

        @keyframes grid {
            from { transform: translateY(0); }
            to { transform: translateY(40px); }
        }

        .container {
            position: relative;
            width: 100%;
            max-width: 1000px;
            backdrop-filter: blur(15px);
            background: rgba(15, 15, 15, .92);
            border: 1px solid rgba(255, 140, 0, .4);
            border-radius: 22px;
            padding: 28px 24px;
            box-shadow: 0 0 30px rgba(255, 120, 0, .3), inset 0 0 20px rgba(255, 120, 0, .15);
            z-index: 2;
            animation: fadeUp .5s ease;
        }

        @keyframes fadeUp {
            0% { opacity: 0; transform: translateY(20px); }
            100% { opacity: 1; transform: translateY(0); }
        }

        .logo {
            text-align: center;
            color: #ff9500;
            font-size: 28px;
            font-weight: 700;
            text-shadow: 0 0 20px #ff8800;
            letter-spacing: 2px;
        }

        .sub {
            text-align: center;
            color: #888;
            font-size: 11px;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }

        .line {
            height: 2px;
            background: linear-gradient(90deg, transparent, #ff9900, transparent);
            margin: 14px 0 20px 0;
        }

        /* ===== ТОСТ-УВЕДОМЛЕНИЯ ===== */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 10px;
            max-width: 380px;
        }

        .toast {
            padding: 14px 20px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.5px;
            animation: slideIn .4s ease;
            box-shadow: 0 0 30px rgba(0,0,0,.5);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,.1);
        }

        .toast-success {
            background: rgba(0, 200, 83, .9);
            color: #fff;
            border-color: rgba(0, 200, 83, .3);
        }

        .toast-error {
            background: rgba(255, 68, 68, .9);
            color: #fff;
            border-color: rgba(255, 68, 68, .3);
        }

        .toast-info {
            background: rgba(255, 140, 0, .9);
            color: #fff;
            border-color: rgba(255, 140, 0, .3);
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateX(100px); }
            to { opacity: 1; transform: translateX(0); }
        }

        /* ===== ВХОД ===== */
        #loginForm {
            max-width: 380px;
            margin: 0 auto;
        }

        .field {
            margin-bottom: 14px;
        }

        .field label {
            display: block;
            color: #ccc;
            font-size: 11px;
            letter-spacing: 1px;
            margin-bottom: 5px;
            text-transform: uppercase;
        }

        .field input,
        .field textarea,
        .field select {
            width: 100%;
            padding: 12px 16px;
            background: rgba(0, 0, 0, .4);
            border: 2px solid #444;
            border-radius: 12px;
            color: #fff;
            font-size: 13px;
            outline: none;
            transition: .3s;
            font-family: 'Orbitron', sans-serif;
        }

        .field textarea {
            min-height: 80px;
            resize: vertical;
            font-family: sans-serif;
        }

        .field select option {
            background: #1a1a1a;
        }

        .field input:focus,
        .field textarea:focus,
        .field select:focus {
            border-color: #ff8c00;
            box-shadow: 0 0 20px rgba(255, 140, 0, .15);
        }

        .field input::placeholder,
        .field textarea::placeholder {
            color: #555;
            font-size: 12px;
        }

        .btn {
            padding: 14px 20px;
            border: none;
            border-radius: 12px;
            background: linear-gradient(90deg, #ff7300, #ffb300);
            color: #fff;
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 1px;
            cursor: pointer;
            transition: .25s;
        }

        .btn:hover {
            transform: scale(1.02);
            box-shadow: 0 0 30px #ff8c00;
        }

        .btn-sm {
            padding: 8px 14px;
            font-size: 11px;
        }

        .btn-danger {
            background: linear-gradient(90deg, #ff4444, #ff6b6b);
        }
        .btn-danger:hover {
            box-shadow: 0 0 30px #ff4444;
        }

        .btn-success {
            background: linear-gradient(90deg, #00c853, #00e676);
        }
        .btn-success:hover {
            box-shadow: 0 0 30px #00e676;
        }

        .btn-outline {
            background: transparent;
            border: 2px solid #ff8c00;
            color: #ff8c00;
        }
        .btn-outline:hover {
            background: rgba(255, 140, 0, .1);
            box-shadow: 0 0 20px rgba(255, 140, 0, .2);
        }

        .btn-block {
            width: 100%;
        }

        .error {
            color: #ff6b6b;
            font-size: 12px;
            text-align: center;
            margin-top: 10px;
            min-height: 20px;
        }

        .success {
            color: #69db7c;
            font-size: 12px;
            text-align: center;
            margin-top: 10px;
            min-height: 20px;
        }

        /* ===== АДМИН-КОНТЕНТ ===== */
        .admin-content {
            display: none;
        }

        .admin-content.active {
            display: block;
        }

        /* ===== ВЕРХНЯЯ ПАНЕЛЬ ===== */
        .admin-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 18px;
            padding-bottom: 14px;
            border-bottom: 1px solid rgba(255, 140, 0, .15);
        }

        .admin-header .user-info {
            color: #aaa;
            font-size: 12px;
            letter-spacing: 0.5px;
        }

        .admin-header .user-info span {
            color: #ff9500;
        }

        .admin-header .stats {
            display: flex;
            gap: 18px;
            flex-wrap: wrap;
        }

        .admin-header .stats .stat-item {
            text-align: center;
        }

        .admin-header .stats .stat-item .num {
            color: #ff9500;
            font-size: 20px;
            font-weight: 700;
        }

        .admin-header .stats .stat-item .label {
            color: #666;
            font-size: 9px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .header-actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        /* ===== ВКЛАДКИ ===== */
        .tabs {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
            margin-bottom: 16px;
            border-bottom: 1px solid rgba(255, 140, 0, .1);
            padding-bottom: 4px;
        }

        .tab {
            padding: 10px 16px;
            background: transparent;
            border: none;
            color: #666;
            font-size: 11px;
            font-family: 'Orbitron', sans-serif;
            cursor: pointer;
            border-radius: 10px 10px 0 0;
            transition: .3s;
            letter-spacing: 0.5px;
        }

        .tab:hover {
            color: #fff;
            background: rgba(255, 140, 0, .05);
        }

        .tab.active {
            color: #ff9500;
            background: rgba(255, 140, 0, .1);
            box-shadow: inset 0 -2px 0 #ff9500;
        }

        .tab-content {
            display: none;
            animation: fadeUp .3s ease;
        }

        .tab-content.active {
            display: block;
        }

        /* ===== КАРТОЧКИ ===== */
        .card {
            background: rgba(0, 0, 0, .3);
            border: 1px solid rgba(255, 140, 0, .08);
            border-radius: 14px;
            padding: 16px 18px;
            margin-bottom: 14px;
        }

        .card .card-title {
            color: #ff9500;
            font-size: 13px;
            margin-bottom: 12px;
            letter-spacing: 0.5px;
        }

        .row {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: end;
        }

        .row .field {
            flex: 1;
            min-width: 130px;
            margin-bottom: 0;
        }

        .row .field label {
            font-size: 10px;
        }

        .row .field input,
        .row .field select {
            padding: 10px 14px;
            font-size: 12px;
        }

        /* ===== ТАБЛИЦА ===== */
        .table-wrap {
            overflow-x: auto;
            position: relative;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11px;
        }

        table th {
            text-align: left;
            color: #ff9500;
            padding: 8px 10px;
            border-bottom: 2px solid rgba(255, 140, 0, .2);
            font-size: 10px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            white-space: nowrap;
        }

        table td {
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255, 255, 255, .04);
            color: #ccc;
            vertical-align: middle;
        }

        table tr:hover td {
            background: rgba(255, 140, 0, .03);
        }

        .status-badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 9px;
            letter-spacing: 0.5px;
        }

        .status-active {
            background: rgba(0, 200, 83, .15);
            color: #69db7c;
        }

        .status-expired {
            background: rgba(255, 77, 77, .15);
            color: #ff6b6b;
        }

        .status-waiting {
            background: rgba(255, 170, 0, .15);
            color: #ffb300;
        }

        .status-full {
            background: rgba(255, 100, 0, .15);
            color: #ff8800;
        }

        .key-value {
            color: #ff9500;
            font-size: 10px;
            word-break: break-all;
            font-family: monospace;
        }

        .copy-btn {
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            font-size: 14px;
            padding: 2px 6px;
            transition: .3s;
        }

        .copy-btn:hover {
            color: #ff9500;
            transform: scale(1.1);
        }

        .table-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap;
            align-items: center;
        }

        .table-tab {
            padding: 5px 14px;
            background: rgba(255, 255, 255, .04);
            border: 1px solid rgba(255, 255, 255, .06);
            border-radius: 20px;
            color: #888;
            font-size: 10px;
            cursor: pointer;
            transition: .3s;
            font-family: 'Orbitron', sans-serif;
        }

        .table-tab.active {
            background: rgba(255, 140, 0, .15);
            border-color: #ff8c00;
            color: #ff9500;
        }

        .table-tab:hover {
            background: rgba(255, 140, 0, .08);
        }

        .table-page {
            display: none;
        }
        .table-page.active {
            display: block;
        }

        .empty-state {
            text-align: center;
            padding: 25px;
            color: #555;
            font-size: 12px;
            letter-spacing: 0.5px;
        }

        .empty-state .icon {
            font-size: 28px;
            margin-bottom: 8px;
            opacity: .3;
        }

        /* ===== ПРОЦЕНТ ОГРАНИЧЕНИЯ ===== */
        .percent-display {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .percent-display input[type="range"] {
            flex: 1;
            accent-color: #ff8c00;
            background: #333;
            height: 4px;
            border-radius: 4px;
        }

        .percent-display .percent-value {
            color: #ff9500;
            font-size: 16px;
            font-weight: 700;
            min-width: 40px;
            text-align: center;
        }

        /* ===== ПОИСК ===== */
        .search-box {
            display: flex;
            gap: 8px;
            align-items: center;
            flex: 1;
            min-width: 150px;
        }

        .search-box input {
            flex: 1;
            padding: 8px 12px;
            background: rgba(0, 0, 0, .4);
            border: 2px solid #444;
            border-radius: 10px;
            color: #fff;
            font-size: 11px;
            outline: none;
            transition: .3s;
            font-family: 'Orbitron', sans-serif;
            min-width: 80px;
        }

        .search-box input:focus {
            border-color: #ff8c00;
        }

        /* ===== ЭКСПОРТ ===== */
        .export-buttons {
            display: flex;
            gap: 6px;
        }

        .export-buttons .btn-sm {
            padding: 5px 12px;
            font-size: 9px;
        }

        /* ===== ИНДИКАТОР ЗАГРУЗКИ ===== */
        .loading-spinner {
            display: none;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, .1);
            border-top: 3px solid #ff9500;
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

        /* ===== ТАЙМЕР В ТАБЛИЦЕ ===== */
        .timer-cell {
            font-family: monospace;
            font-size: 11px;
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

        /* ===== МАССОВОЕ УДАЛЕНИЕ ===== */
        .bulk-actions {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid rgba(255, 255, 255, .05);
        }

        .bulk-actions .btn-sm {
            font-size: 9px;
            padding: 4px 12px;
        }

        /* ===== АДАПТИВ ===== */
        @media (max-width: 768px) {
            .container {
                padding: 16px 12px;
            }
            .admin-header {
                flex-direction: column;
                align-items: stretch;
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
                font-size: 9px;
            }
            table th,
            table td {
                padding: 4px 6px;
            }
            .tabs {
                gap: 2px;
            }
            .tab {
                padding: 6px 10px;
                font-size: 9px;
            }
            .toast-container {
                top: 10px;
                right: 10px;
                max-width: 280px;
            }
            .toast {
                padding: 10px 14px;
                font-size: 10px;
            }
            .search-box {
                min-width: 100%;
            }
            .export-buttons .btn-sm {
                padding: 4px 8px;
                font-size: 8px;
            }
        }

        ::-webkit-scrollbar {
            width: 4px;
            height: 4px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, .05);
        }
        ::-webkit-scrollbar-thumb {
            background: #ff8c00;
            border-radius: 4px;
        }
    </style>
</head>
<body>

    <!-- ===== ТОСТ-КОНТЕЙНЕР ===== -->
    <div class="toast-container" id="toastContainer"></div>

    <div class="container">

        <div class="logo">ORANGMODS</div>
        <div class="sub">ADMIN PANEL · API</div>
        <div class="line"></div>

        <!-- ===== ВХОД ===== -->
        <div id="loginForm">
            <div class="field">
                <label>Логин</label>
                <input type="text" id="loginInput" placeholder="Введите логин" value="" autocomplete="username" />
            </div>
            <div class="field">
                <label>Пароль</label>
                <input type="password" id="passInput" placeholder="Введите пароль" value="" autocomplete="current-password" />
            </div>
            <button class="btn btn-block" id="loginBtn">ВОЙТИ</button>
            <div class="error" id="errorMsg"></div>
            <div class="success" id="apiStatus"></div>
        </div>

        <!-- ===== АДМИН-ПАНЕЛЬ ===== -->
        <div class="admin-content" id="adminContent">

            <!-- Верхняя панель -->
            <div class="admin-header">
                <div class="user-info">
                    👤 <span id="userDisplay">Admin</span>
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
                    <button class="btn btn-sm btn-outline" id="refreshBtn">🔄</button>
                    <button class="btn btn-sm btn-danger" id="logoutBtn" style="width:auto;padding:6px 14px;font-size:10px;">ВЫЙТИ</button>
                </div>
            </div>

            <!-- Вкладки -->
            <div class="tabs">
                <button class="tab active" data-tab="tab1">📋 Ключи</button>
                <button class="tab" data-tab="tab2">➕ Добавить</button>
                <button class="tab" data-tab="tab3">📢 Уведомления</button>
                <button class="tab" data-tab="tab4">🎯 Реклама</button>
            </div>

            <!-- ===== ВКЛАДКА 1: КЛЮЧИ ===== -->
            <div class="tab-content active" id="tab1">
                <div class="card">
                    <div class="table-tabs">
                        <button class="table-tab active" data-page="page1">🟢 Активные / Ожидают</button>
                        <button class="table-tab" data-page="page2">🔴 Закончились</button>

                        <div class="search-box">
                            <input type="text" id="searchInput" placeholder="🔍 Поиск..." />
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
                                        <th style="width:30px;">
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
                                        <th style="width:40px;"></th>
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
                                        <th style="width:30px;">
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
                                        <th style="width:40px;"></th>
                                    </tr>
                                </thead>
                                <tbody id="expiredKeysTable"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="bulk-actions">
                        <span style="color:#666;font-size:9px;">Выбрано: <span id="selectedCount">0</span></span>
                        <button class="btn btn-sm btn-danger" id="bulkDeleteBtn">🗑️ Удалить выбранные</button>
                    </div>
                </div>
            </div>

            <!-- ===== ВКЛАДКА 2: ДОБАВИТЬ КЛЮЧ ===== -->
            <div class="tab-content" id="tab2">
                <div class="card">
                    <div class="card-title">🔑 Создать новый ключ</div>
                    <div class="row">
                        <div class="field">
                            <label>Название</label>
                            <input type="text" id="keyName" placeholder="Промо 7 дней" />
                        </div>
                        <div class="field" style="min-width:100px;">
                            <label>Тип</label>
                            <select id="keyType">
                                <option value="DAY">Дни</option>
                                <option value="HOUR">Часы</option>
                            </select>
                        </div>
                        <div class="field" style="min-width:80px;">
                            <label>Кол-во</label>
                            <input type="number" id="keyDuration" value="7" min="1" max="365" />
                        </div>
                        <div class="field" style="min-width:80px;">
                            <label>Устройств</label>
                            <input type="number" id="keyDevices" value="5" min="1" max="999" />
                        </div>
                    </div>
                    <div class="row" style="margin-top:10px;">
                        <div class="field" style="min-width:200px;flex:2;">
                            <label>Ограничение % (40-95)</label>
                            <div class="percent-display">
                                <input type="range" min="40" max="95" value="70" id="keyPercentRange" />
                                <span class="percent-value" id="keyPercentDisplay">70%</span>
                            </div>
                        </div>
                        <div class="field" style="min-width:120px;flex:0;">
                            <label>Авто-название</label>
                            <button class="btn btn-sm btn-outline" id="generateAutoBtn" style="width:100%;margin-top:0;">🎲</button>
                        </div>
                    </div>
                    <button class="btn btn-sm btn-success" id="generateKeyBtn" style="margin-top:12px;width:100%;">
                        <span class="btn-text">➕ Сгенерировать ключ</span>
                        <span class="loading-spinner"></span>
                    </button>
                    <div class="success" id="keyGenResult"></div>
                </div>

                <div class="card">
                    <div class="card-title">🗑️ Удалить ключ</div>
                    <div class="row">
                        <div class="field">
                            <label>Введите ключ</label>
                            <input type="text" id="deleteKeyInput" placeholder="OrangMods-7DAY-..." />
                        </div>
                        <button class="btn btn-sm btn-danger" id="deleteKeyBtn" style="min-width:100px;">Удалить</button>
                    </div>
                    <div class="error" id="deleteResult"></div>
                </div>
            </div>

            <!-- ===== ВКЛАДКА 3: УВЕДОМЛЕНИЯ ===== -->
            <div class="tab-content" id="tab3">
                <div class="card">
                    <div class="card-title">📢 Отправить уведомление</div>
                    <div class="field">
                        <label>Текст</label>
                        <textarea id="notifyText" placeholder="Введите текст уведомления..."></textarea>
                    </div>
                    <button class="btn btn-sm btn-success" id="sendNotifyBtn">
                        <span class="btn-text">📨 Отправить всем</span>
                        <span class="loading-spinner"></span>
                    </button>
                    <div class="success" id="notifyResult"></div>
                </div>
                <div class="card">
                    <div class="card-title">📋 История</div>
                    <div id="notifyHistory">
                        <div class="empty-state">
                            <div class="icon">📭</div>
                            <div>Пока нет уведомлений</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ===== ВКЛАДКА 4: РЕКЛАМА ===== -->
            <div class="tab-content" id="tab4">
                <div class="card">
                    <div class="card-title">🎯 Настройка рекламы</div>
                    <div class="field">
                        <label>HTML-код</label>
                        <textarea id="adHtml" placeholder="<div style='...'>Реклама</div>"></textarea>
                    </div>
                    <div class="row">
                        <div class="field" style="min-width:150px;flex:0;">
                            <label>Закрываемая?</label>
                            <select id="adClosable">
                                <option value="1">✅ Да</option>
                                <option value="0">❌ Нет</option>
                            </select>
                        </div>
                        <button class="btn btn-sm btn-success" id="saveAdBtn" style="min-width:120px;">
                            <span class="btn-text">💾 Сохранить</span>
                            <span class="loading-spinner"></span>
                        </button>
                    </div>
                    <div class="success" id="adResult"></div>
                </div>
                <div class="card">
                    <div class="card-title">👁️ Предпросмотр</div>
                    <div id="adPreview" style="background:rgba(0,0,0,.5);border-radius:12px;padding:20px;min-height:80px;display:flex;align-items:center;justify-content:center;color:#555;border:1px dashed rgba(255,140,0,.2);font-size:12px;">
                        Реклама не настроена
                    </div>
                    <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;">
                        <label style="color:#888;font-size:10px;display:flex;align-items:center;gap:6px;">
                            <input type="checkbox" id="adShowPreview" checked /> Показывать
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

                    const config = {
                        ...options,
                        headers
                    };

                    const response = await fetch(url, config);
                    if (response.status === 401) {
                        if (this.onUnauthorized) {
                            this.onUnauthorized();
                        }
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

                async info() {
                    return this._fetch('/info');
                }

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

                async dashboard() {
                    return this._fetch('/dashboard');
                }

                async getKeys() {
                    return this._fetch('/keys');
                }

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
                    return this._fetch(`/keys/${id}`, {
                        method: 'DELETE'
                    });
                }

                async getNotifications() {
                    return this._fetch('/notifications');
                }

                async sendNotification(text) {
                    return this._fetch('/notifications', {
                        method: 'POST',
                        body: JSON.stringify({ text })
                    });
                }

                async getAds() {
                    return this._fetch('/ads');
                }

                async saveAds(html, isClosable) {
                    return this._fetch('/ads', {
                        method: 'POST',
                        body: JSON.stringify({ html, is_closable: isClosable })
                    });
                }
            }

            // ============================================================
            // 2. ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
            // ============================================================
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
            let isAuthorized = false;

            // ============================================================
            // 3. ТОСТЫ
            // ============================================================
            function showToast(message, type = 'info') {
                const container = document.getElementById('toastContainer');
                const toast = document.createElement('div');
                toast.className = `toast toast-${type}`;
                toast.textContent = message;
                container.appendChild(toast);
                setTimeout(() => {
                    toast.style.opacity = '0';
                    toast.style.transform = 'translateX(100px)';
                    setTimeout(() => toast.remove(), 400);
                }, 3500);
            }

            // ============================================================
            // 4. РЕНДЕРИНГ
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
                    activeKeysTable.innerHTML =
                        `<tr><td colspan="10" class="empty-state"><div class="icon">📭</div>Нет активных ключей</td></tr>`;
                } else {
                    activeKeysTable.innerHTML = active.map(k => renderKeyRow(k)).join('');
                }

                if (expired.length === 0) {
                    expiredKeysTable.innerHTML =
                        `<tr><td colspan="10" class="empty-state"><div class="icon">🎉</div>Нет истекших ключей</td></tr>`;
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
                            <button class="copy-btn" data-key="${key.key_value}" title="Копировать">📋</button>
                        </td>
                        <td>${key.name || '-'}</td>
                        <td>${key.type}</td>
                        <td style="color:#ff9500;">${key.max_percent || 95}%</td>
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
                            <div>Пока нет уведомлений</div>
                        </div>
                    `;
                    return;
                }
                notifyHistory.innerHTML = cache.notifications.slice().reverse().map(n => `
                    <div style="padding:8px 12px;background:rgba(255,255,255,.03);border-radius:8px;margin-bottom:6px;border-left:3px solid #ff8c00;">
                        <div style="color:#fff;font-size:12px;font-family:sans-serif;">${n.text}</div>
                        <div style="color:#555;font-size:9px;margin-top:3px;">${new Date(n.created_at).toLocaleString()}</div>
                    </div>
                `).join('');
            }

            function renderAd() {
                const show = adShowPreview.checked;
                if (!show || !cache.ads.html) {
                    adPreview.innerHTML = `<span style="font-size:12px;color:#555;">${cache.ads.html ? 'Предпросмотр отключен' : 'Реклама не настроена'}</span>`;
                    return;
                }
                adPreview.innerHTML = cache.ads.html;
                adHtml.value = cache.ads.html || '';
                adClosable.value = cache.ads.is_closable ? '1' : '0';
            }

            function updateSelectedCount() {
                const total = selectedActiveSet.size + selectedExpiredSet.size;
                selectedCount.textContent = total;
            }

            // ============================================================
            // 5. ЗАГРУЗКА ДАННЫХ
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
                        // обработаем в колбэке
                    } else {
                        showToast('❌ Ошибка загрузки дашборда: ' + err.message, 'error');
                    }
                    throw err;
                }
            }

            async function loadKeys() {
                try {
                    const data = await api.getKeys();
                    cache.keys = data.keys || [];
                    renderKeys(searchInput.value.trim());
                } catch (err) {
                    if (err.message === 'Token expired') return;
                    showToast('❌ Ошибка загрузки ключей: ' + err.message, 'error');
                }
            }

            async function loadNotifications() {
                try {
                    const data = await api.getNotifications();
                    cache.notifications = data.notifications || [];
                    renderNotifications();
                } catch (err) {
                    if (err.message === 'Token expired') return;
                    showToast('❌ Ошибка загрузки уведомлений: ' + err.message, 'error');
                }
            }

            async function loadAds() {
                try {
                    const data = await api.getAds();
                    cache.ads = data || { html: '', is_closable: true };
                    renderAd();
                } catch (err) {
                    if (err.message === 'Token expired') return;
                    showToast('❌ Ошибка загрузки рекламы: ' + err.message, 'error');
                }
            }

            function renderAll() {
                renderKeys(searchInput.value.trim());
                renderNotifications();
                renderAd();
            }

            // ============================================================
            // 6. API КОЛБЭК НА 401
            // ============================================================
            api.onUnauthorized = function() {
                showToast('⏳ Сессия истекла, войдите снова', 'error');
                logout();
            };

            // ============================================================
            // 7. АВТОРИЗАЦИЯ
            // ============================================================
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

                try {
                    const data = await api.login(login, pass);
                    if (data.success && data.token) {
                        isAuthorized = true;
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
            }

            function showAdminPanel() {
                loginForm.style.display = 'none';
                adminContent.classList.add('active');
                userDisplay.textContent = loginInput.value.trim() || 'Admin';
            }

            function logout() {
                isAuthorized = false;
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
                showToast('👋 Вы вышли', 'info');
            }

            // ============================================================
            // 8. СОБЫТИЯ
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
                try {
                    await loadDashboard();
                } catch (e) {}
                this.classList.remove('loading');
            });

            searchInput.addEventListener('input', function() {
                renderKeys(this.value.trim());
            });

            document.getElementById('exportCSV').addEventListener('click', () => exportData('CSV'));
            document.getElementById('exportJSON').addEventListener('click', () => exportData('JSON'));

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
                    if (found) idsToDelete.push(found.id);
                });

                let deleted = 0;
                for (const id of idsToDelete) {
                    try {
                        await api.deleteKey(id);
                        deleted++;
                    } catch (err) {
                        showToast('❌ Ошибка удаления ключа: ' + err.message, 'error');
                    }
                }

                selectedActiveSet.clear();
                selectedExpiredSet.clear();
                showToast(`✅ Удалено ${deleted} ключей`, 'success');
                await loadDashboard();
            });

            document.getElementById('generateAutoBtn').addEventListener('click', function() {
                const prefixes = ['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Zeta', 'Eta', 'Theta', 'Iota', 'Kappa',
                    'Lambda', 'Mu', 'Nu', 'Xi', 'Omicron', 'Pi', 'Rho', 'Sigma', 'Tau', 'Upsilon', 'Phi', 'Chi', 'Psi',
                    'Omega'
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
                    await loadDashboard();
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
                    await loadDashboard();
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
                    await loadNotifications();
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
                    await loadAds();
                } catch (err) {
                    adResult.textContent = '❌ ' + err.message;
                    adResult.style.color = '#ff6b6b';
                    showToast('❌ Ошибка: ' + err.message, 'error');
                }
                this.classList.remove('loading');
            });

            adShowPreview.addEventListener('change', renderAd);

            // ============================================================
            // 9. ВКЛАДКИ
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
            // 10. СТАРТ
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
                    loginBtn.textContent = 'ВОЙТИ';
                }
                console.log('🔐 OrangMods Admin Panel (REST API)');
            })();

        })();
    </script>

</body>
</html>"""

# Сохраняем HTML
with open(STATIC_DIR / "index.html", "w", encoding="utf-8") as f:
    f.write(ADMIN_HTML)

# ============================================================
# API МАРШРУТЫ (адаптированы под фронтенд)
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def serve_admin():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
async def health_check():
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
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

# Информация о API
@app.get("/api/info")
async def api_info():
    return {"status": "online", "version": "1.0.0", "timestamp": datetime.now().isoformat()}

# Логин
@app.post("/api/login")
async def admin_login(login_data: AdminLogin, request: Request):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash FROM admins WHERE username = ? AND is_active = 1",
            (login_data.login,)
        )
        admin = cursor.fetchone()
        if not admin or not verify_password(login_data.password, admin[2]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"sub": str(admin[0]), "username": admin[1]})
        
        client_ip = request.client.host if request.client else "unknown"
        log_action(admin[0], "login", f"Login from {client_ip}", client_ip)
        
        return {"success": True, "token": token, "username": admin[1]}

# Дашборд (все данные сразу)
@app.get("/api/dashboard")
async def get_dashboard(current_admin: dict = Depends(get_current_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Статистика
        cursor.execute("SELECT COUNT(*) FROM keys")
        total_keys = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM keys WHERE status = 'active'")
        active_keys = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM keys WHERE status = 'expired'")
        expired_keys = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(used_devices) FROM keys")
        total_devices = cursor.fetchone()[0] or 0
        
        stats = {
            "total_keys": total_keys,
            "active_keys": active_keys,
            "expired_keys": expired_keys,
            "total_devices": total_devices
        }
        
        # Ключи
        cursor.execute("""
            SELECT id, key_value, name, type, duration, max_devices, max_percent, 
                   used_devices, first_activation, status, created_at
            FROM keys
            ORDER BY created_at DESC
        """)
        keys = cursor.fetchall()
        
        keys_list = []
        for key in keys:
            key_dict = dict(key)
            # Вычисляем время
            if key_dict['status'] == 'active' and key_dict['first_activation']:
                try:
                    first_act = datetime.fromisoformat(key_dict['first_activation'].replace(' ', 'T'))
                    now = datetime.now()
                    delta = now - first_act
                    if key_dict['type'] == 'DAY':
                        total_seconds = key_dict['duration'] * 24 * 3600
                    else:
                        total_seconds = key_dict['duration'] * 3600
                    elapsed = delta.total_seconds()
                    left = max(0, total_seconds - elapsed)
                    hours = int(left // 3600)
                    minutes = int((left % 3600) // 60)
                    key_dict['time_left'] = f"{hours}ч {minutes}м"
                    key_dict['time_left_seconds'] = left
                except:
                    key_dict['time_left'] = 'Ошибка'
                    key_dict['time_left_seconds'] = 0
            else:
                key_dict['time_left'] = 'НЕТ'
                key_dict['time_left_seconds'] = 0
            
            keys_list.append(key_dict)
        
        # Уведомления
        cursor.execute("SELECT id, text, created_at FROM notifications ORDER BY created_at DESC LIMIT 50")
        notifications = [dict(n) for n in cursor.fetchall()]
        
        # Реклама
        cursor.execute("SELECT html, is_closable FROM advertisements WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1")
        ad = cursor.fetchone()
        ads = {"html": ad[0] if ad else "", "is_closable": bool(ad[1]) if ad else True}
        
        return {
            "stats": stats,
            "keys": keys_list,
            "notifications": notifications,
            "ads": ads
        }

# Ключи
@app.get("/api/keys")
async def get_keys(current_admin: dict = Depends(get_current_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, key_value, name, type, duration, max_devices, max_percent, 
                   used_devices, first_activation, status, created_at
            FROM keys
            ORDER BY created_at DESC
        """)
        keys = cursor.fetchall()
        
        keys_list = []
        for key in keys:
            key_dict = dict(key)
            if key_dict['status'] == 'active' and key_dict['first_activation']:
                try:
                    first_act = datetime.fromisoformat(key_dict['first_activation'].replace(' ', 'T'))
                    now = datetime.now()
                    delta = now - first_act
                    if key_dict['type'] == 'DAY':
                        total_seconds = key_dict['duration'] * 24 * 3600
                    else:
                        total_seconds = key_dict['duration'] * 3600
                    elapsed = delta.total_seconds()
                    left = max(0, total_seconds - elapsed)
                    hours = int(left // 3600)
                    minutes = int((left % 3600) // 60)
                    key_dict['time_left'] = f"{hours}ч {minutes}м"
                    key_dict['time_left_seconds'] = left
                except:
                    key_dict['time_left'] = 'Ошибка'
                    key_dict['time_left_seconds'] = 0
            else:
                key_dict['time_left'] = 'НЕТ'
                key_dict['time_left_seconds'] = 0
            
            keys_list.append(key_dict)
        
        return {"keys": keys_list}

@app.post("/api/keys")
async def create_key(key_data: KeyCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    key_value = generate_key_code(key_data.type, key_data.duration)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO keys (key_value, name, type, duration, max_devices, max_percent, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?)
        """, (key_value, key_data.name, key_data.type, key_data.duration, key_data.max_devices, key_data.max_percent, current_admin["id"]))
        
        key_id = cursor.lastrowid
        
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
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key_value FROM keys WHERE id = ?", (key_id,))
        key = cursor.fetchone()
        if not key:
            raise HTTPException(status_code=404, detail="Key not found")
        
        cursor.execute("DELETE FROM keys WHERE id = ?", (key_id,))
        
        client_ip = request.client.host if request else "unknown"
        log_action(current_admin["id"], "delete_key", f"Deleted key: {key['key_value']}", client_ip)
        
        return {"message": "Key deleted successfully"}

# Уведомления
@app.get("/api/notifications")
async def get_notifications(current_admin: dict = Depends(get_current_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, text, created_at FROM notifications ORDER BY created_at DESC LIMIT 50")
        notifications = [dict(n) for n in cursor.fetchall()]
        return {"notifications": notifications}

@app.post("/api/notifications")
async def create_notification(notif_data: NotificationCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notifications (text) VALUES (?)",
            (notif_data.text,)
        )
        
        client_ip = request.client.host if request else "unknown"
        log_action(current_admin["id"], "create_notification", f"Created notification: {notif_data.text[:50]}...", client_ip)
        
        return {"message": "Notification created", "id": cursor.lastrowid}

# Реклама
@app.get("/api/ads")
async def get_ads():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT html, is_closable FROM advertisements WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1")
        ad = cursor.fetchone()
        if ad:
            return {"html": ad[0], "is_closable": bool(ad[1])}
        return {"html": "", "is_closable": True}

@app.post("/api/ads")
async def save_ads(ad_data: AdCreate, current_admin: dict = Depends(get_current_admin), request: Request = None):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE advertisements SET is_active = 0 WHERE is_active = 1")
        cursor.execute(
            "INSERT INTO advertisements (html, is_closable, is_active) VALUES (?, ?, 1)",
            (ad_data.html, 1 if ad_data.is_closable else 0)
        )
        
        client_ip = request.client.host if request else "unknown"
        log_action(current_admin["id"], "update_ad", "Updated advertisement", client_ip)
        
        return {"message": "Advertisement saved"}

# Обработка ошибок
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

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
      )
