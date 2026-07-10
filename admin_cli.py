#!/usr/bin/env python3
"""
OrangMods Admin CLI - Терминальная админ-панель
Для Termux / Linux / macOS
"""

import os
import sys
import json
import requests
import time
from datetime import datetime
from typing import Optional, Dict, Any, List

# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

API_URL = os.getenv("ORANGMODS_API", "https://orangmods-api.onrender.com")
TOKEN_FILE = os.path.expanduser("~/.orangmods_token")

# ============================================================
# ЦВЕТА ДЛЯ ТЕРМИНАЛА
# ============================================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    CLEAR = '\033[2J\033[H'

def c(text: str, color: str = Colors.RESET) -> str:
    return f"{color}{text}{Colors.RESET}"

# ============================================================
# ОЧИСТКА ЭКРАНА
# ============================================================

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

# ============================================================
# РАБОТА С ТОКЕНОМ
# ============================================================

def save_token(token: str):
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)
    os.chmod(TOKEN_FILE, 0o600)

def load_token() -> Optional[str]:
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            return f.read().strip()
    return None

def clear_token():
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)

# ============================================================
# API КЛИЕНТ
# ============================================================

class OrangModsAPI:
    def __init__(self, base_url: str = API_URL):
        self.base_url = base_url.rstrip('/')
        self.token = load_token()
        self.username = None

    def _headers(self) -> dict:
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def _request(self, method: str, endpoint: str, data: dict = None) -> dict:
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(
                method,
                url,
                headers=self._headers(),
                json=data,
                timeout=10
            )
            if response.status_code == 401:
                clear_token()
                self.token = None
                raise Exception("Session expired. Please login again.")
            return response.json()
        except requests.exceptions.ConnectionError:
            raise Exception("❌ Cannot connect to server")
        except requests.exceptions.Timeout:
            raise Exception("❌ Request timeout")
        except Exception as e:
            raise Exception(f"❌ Error: {str(e)}")

    def login(self, username: str, password: str) -> bool:
        try:
            result = self._request('POST', '/api/login', {'login': username, 'password': password})
            if result.get('success') and result.get('token'):
                self.token = result['token']
                self.username = result.get('username', username)
                save_token(self.token)
                return True
            return False
        except Exception as e:
            print(f"{Colors.RED}{e}{Colors.RESET}")
            return False

    def info(self) -> dict:
        return self._request('GET', '/api/info')

    def dashboard(self) -> dict:
        return self._request('GET', '/api/dashboard')

    def get_keys(self) -> list:
        result = self._request('GET', '/api/keys')
        return result.get('keys', [])

    def create_key(self, name: str, key_type: str, duration: int, max_devices: int, max_percent: int) -> dict:
        return self._request('POST', '/api/keys', {
            'name': name,
            'type': key_type,
            'duration': duration,
            'max_devices': max_devices,
            'max_percent': max_percent
        })

    def delete_key(self, key_id: int) -> dict:
        return self._request('DELETE', f'/api/keys/{key_id}')

    def get_notifications(self) -> list:
        result = self._request('GET', '/api/notifications')
        return result.get('notifications', [])

    def send_notification(self, text: str) -> dict:
        return self._request('POST', '/api/notifications', {'text': text})

    def get_ads(self) -> dict:
        return self._request('GET', '/api/ads')

    def save_ads(self, html: str, is_closable: bool) -> dict:
        return self._request('POST', '/api/ads', {
            'html': html,
            'is_closable': is_closable
        })

# ============================================================
# UI КОМПОНЕНТЫ
# ============================================================

def print_header(title: str):
    clear()
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("=" * 50)
    print(f"  🍊 ORANGMODS ADMIN PANEL".center(50))
    print("=" * 50)
    print(f"{Colors.RESET}")
    print(f"{Colors.DIM}  {title}{Colors.RESET}")
    print()

def print_menu(items: list) -> int:
    print(f"{Colors.YELLOW}Выберите действие:{Colors.RESET}")
    print()
    for i, (key, label, color) in enumerate(items):
        if color:
            print(f"  {Colors.BOLD}{key}{Colors.RESET}. {color}{label}{Colors.RESET}")
        else:
            print(f"  {Colors.BOLD}{key}{Colors.RESET}. {label}")
    print()
    try:
        choice = input(f"{Colors.GREEN}➜ {Colors.RESET}")
        return int(choice.strip())
    except ValueError:
        return -1

def print_keys_table(keys: list):
    if not keys:
        print(f"{Colors.DIM}  Нет ключей{Colors.RESET}")
        return

    print(f"{Colors.BOLD}{Colors.CYAN}")
    print(f"  {'ID':>4} {'Ключ':<35} {'Название':<20} {'Тип':<6} {'%':<5} {'Статус':<10}")
    print(f"  {'-'*4} {'-'*35} {'-'*20} {'-'*6} {'-'*5} {'-'*10}")
    print(f"{Colors.RESET}")

    for key in keys:
        status_color = Colors.GREEN if key['status'] == 'active' else Colors.YELLOW if key['status'] == 'waiting' else Colors.RED
        status_icon = '🟢' if key['status'] == 'active' else '🟡' if key['status'] == 'waiting' else '🔴'
        print(f"  {key['id']:>4} {key['key_value']:<35} {key['name']:<20} {key['type']:<6} {key['max_percent']:>3}%  {status_color}{status_icon} {key['status']:<8}{Colors.RESET}")

def print_notifications(notifications: list):
    if not notifications:
        print(f"{Colors.DIM}  Нет уведомлений{Colors.RESET}")
        return

    for n in notifications[:10]:
        print(f"  {Colors.CYAN}📢 {n['text']}{Colors.RESET}")
        print(f"  {Colors.DIM}   {n['created_at']}{Colors.RESET}")
        print()

# ============================================================
# ЭКРАНЫ
# ============================================================

def login_screen(api: OrangModsAPI) -> bool:
    print_header("🔐 АВТОРИЗАЦИЯ")

    print(f"{Colors.DIM}  Сервер: {api.base_url}{Colors.RESET}")
    print()

    username = input(f"{Colors.GREEN}👤 Логин: {Colors.RESET}").strip()
    password = input(f"{Colors.GREEN}🔑 Пароль: {Colors.RESET}").strip()

    if api.login(username, password):
        print(f"\n{Colors.GREEN}✅ Успешный вход!{Colors.RESET}")
        time.sleep(1)
        return True
    else:
        print(f"\n{Colors.RED}❌ Неверный логин или пароль{Colors.RESET}")
        time.sleep(2)
        return False

def main_menu(api: OrangModsAPI):
    while True:
        print_header("📋 ГЛАВНОЕ МЕНЮ")

        try:
            info = api.info()
            print(f"  {Colors.DIM}Статус: {Colors.GREEN}онлайн{Colors.RESET}  |  Версия: {info.get('version', '1.0.0')}{Colors.RESET}")
        except:
            print(f"  {Colors.RED}⚠️ Сервер недоступен{Colors.RESET}")

        print()

        items = [
            ('1', '📊 Статистика', Colors.CYAN),
            ('2', '🔑 Управление ключами', Colors.YELLOW),
            ('3', '📢 Уведомления', Colors.BLUE),
            ('4', '🎯 Реклама', Colors.MAGENTA),
            ('5', '📋 Логи', Colors.DIM),
            ('0', '🚪 Выход', Colors.RED),
        ]

        choice = print_menu(items)

        if choice == 1:
            stats_screen(api)
        elif choice == 2:
            keys_menu(api)
        elif choice == 3:
            notifications_menu(api)
        elif choice == 4:
            ads_menu(api)
        elif choice == 5:
            logs_screen(api)
        elif choice == 0:
            clear()
            print(f"{Colors.GREEN}👋 До свидания!{Colors.RESET}")
            sys.exit(0)

def stats_screen(api: OrangModsAPI):
    print_header("📊 СТАТИСТИКА")

    try:
        data = api.dashboard()
        stats = data.get('stats', {})
        keys = data.get('keys', [])

        print(f"  {Colors.BOLD}📈 ОБЩАЯ СТАТИСТИКА{Colors.RESET}")
        print()
        print(f"  {Colors.CYAN}Всего ключей:{Colors.RESET}     {stats.get('total_keys', 0)}")
        print(f"  {Colors.GREEN}Активных:{Colors.RESET}        {stats.get('active_keys', 0)}")
        print(f"  {Colors.RED}Истекших:{Colors.RESET}         {stats.get('expired_keys', 0)}")
        print(f"  {Colors.YELLOW}Устройств:{Colors.RESET}       {stats.get('total_devices', 0)}")
        print()
        print(f"  {Colors.DIM}Последние 5 ключей:{Colors.RESET}")
        print()
        print_keys_table(keys[:5])

    except Exception as e:
        print(f"{Colors.RED}{e}{Colors.RESET}")

    input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.RESET}")

def keys_menu(api: OrangModsAPI):
    while True:
        print_header("🔑 УПРАВЛЕНИЕ КЛЮЧАМИ")

        try:
            keys = api.get_keys()
            print_keys_table(keys)
        except Exception as e:
            print(f"{Colors.RED}{e}{Colors.RESET}")

        print()
        items = [
            ('1', '➕ Создать ключ', Colors.GREEN),
            ('2', '🗑️ Удалить ключ', Colors.RED),
            ('3', '🔄 Обновить список', Colors.CYAN),
            ('0', '◀️ Назад', Colors.DIM),
        ]

        choice = print_menu(items)

        if choice == 1:
            create_key_screen(api)
        elif choice == 2:
            delete_key_screen(api)
        elif choice == 3:
            continue
        elif choice == 0:
            break

def create_key_screen(api: OrangModsAPI):
    print_header("➕ СОЗДАНИЕ КЛЮЧА")

    name = input(f"{Colors.GREEN}Название: {Colors.RESET}").strip()
    if not name:
        name = "Ключ"

    print(f"\n{Colors.DIM}Тип:{Colors.RESET}")
    print("  1. DAY (дни)")
    print("  2. HOUR (часы)")
    type_choice = input(f"{Colors.GREEN}➜ {Colors.RESET}").strip()

    key_type = "DAY" if type_choice == "1" else "HOUR"

    duration = input(f"{Colors.GREEN}Количество ({'дней' if key_type == 'DAY' else 'часов'}): {Colors.RESET}").strip()
    try:
        duration = int(duration)
    except:
        duration = 7

    max_devices = input(f"{Colors.GREEN}Макс. устройств: {Colors.RESET}").strip()
    try:
        max_devices = int(max_devices)
    except:
        max_devices = 1

    max_percent = input(f"{Colors.GREEN}Лимит % (40-95): {Colors.RESET}").strip()
    try:
        max_percent = int(max_percent)
        if max_percent < 40 or max_percent > 95:
            max_percent = 70
    except:
        max_percent = 70

    print(f"\n{Colors.DIM}Создание...{Colors.RESET}")

    try:
        result = api.create_key(name, key_type, duration, max_devices, max_percent)
        print(f"\n{Colors.GREEN}✅ Ключ создан!{Colors.RESET}")
        print(f"  {Colors.CYAN}{result.get('key_value')}{Colors.RESET}")
        print(f"  ID: {result.get('id')}")
    except Exception as e:
        print(f"\n{Colors.RED}{e}{Colors.RESET}")

    input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.RESET}")

def delete_key_screen(api: OrangModsAPI):
    print_header("🗑️ УДАЛЕНИЕ КЛЮЧА")

    try:
        keys = api.get_keys()
        print_keys_table(keys)
    except Exception as e:
        print(f"{Colors.RED}{e}{Colors.RESET}")
        input("Нажмите Enter...")
        return

    print()
    key_id = input(f"{Colors.GREEN}ID ключа для удаления: {Colors.RESET}").strip()

    try:
        key_id = int(key_id)
        confirm = input(f"{Colors.RED}Удалить ключ ID {key_id}? (y/N): {Colors.RESET}").strip().lower()
        if confirm == 'y':
            api.delete_key(key_id)
            print(f"{Colors.GREEN}✅ Ключ удален{Colors.RESET}")
    except ValueError:
        print(f"{Colors.RED}❌ Неверный ID{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}{e}{Colors.RESET}")

    input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.RESET}")

def notifications_menu(api: OrangModsAPI):
    while True:
        print_header("📢 УВЕДОМЛЕНИЯ")

        try:
            notifications = api.get_notifications()
            print_notifications(notifications)
        except Exception as e:
            print(f"{Colors.RED}{e}{Colors.RESET}")

        print()
        items = [
            ('1', '📨 Отправить уведомление', Colors.GREEN),
            ('0', '◀️ Назад', Colors.DIM),
        ]

        choice = print_menu(items)

        if choice == 1:
            send_notification_screen(api)
        elif choice == 0:
            break

def send_notification_screen(api: OrangModsAPI):
    print_header("📨 ОТПРАВКА УВЕДОМЛЕНИЯ")

    text = input(f"{Colors.GREEN}Текст: {Colors.RESET}").strip()

    if not text:
        print(f"{Colors.RED}❌ Текст не может быть пустым{Colors.RESET}")
    else:
        try:
            api.send_notification(text)
            print(f"\n{Colors.GREEN}✅ Уведомление отправлено!{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}{e}{Colors.RESET}")

    input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.RESET}")

def ads_menu(api: OrangModsAPI):
    while True:
        print_header("🎯 РЕКЛАМА")

        try:
            ads = api.get_ads()
            print(f"  {Colors.CYAN}Текущая реклама:{Colors.RESET}")
            print(f"  {Colors.DIM}{ads.get('html', '')[:200]}{Colors.RESET}")
            print(f"  {Colors.DIM}Закрываемая: {'✅' if ads.get('is_closable') else '❌'}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}{e}{Colors.RESET}")

        print()
        items = [
            ('1', '📝 Редактировать рекламу', Colors.GREEN),
            ('0', '◀️ Назад', Colors.DIM),
        ]

        choice = print_menu(items)

        if choice == 1:
            edit_ads_screen(api)
        elif choice == 0:
            break

def edit_ads_screen(api: OrangModsAPI):
    print_header("📝 РЕДАКТИРОВАНИЕ РЕКЛАМЫ")

    try:
        ads = api.get_ads()
        current_html = ads.get('html', '')
        current_closable = ads.get('is_closable', True)

        print(f"{Colors.DIM}Текущий HTML:{Colors.RESET}")
        print(f"{Colors.DIM}{current_html[:200]}{Colors.RESET}\n")

        print(f"{Colors.DIM}Введите новый HTML (или оставьте пустым для удаления):{Colors.RESET}")
        html = input(f"{Colors.GREEN}HTML: {Colors.RESET}").strip()

        closable = input(f"{Colors.GREEN}Закрываемая? (y/N): {Colors.RESET}").strip().lower()
        is_closable = closable == 'y'

        api.save_ads(html if html else '', is_closable)
        print(f"\n{Colors.GREEN}✅ Реклама сохранена{Colors.RESET}")

    except Exception as e:
        print(f"\n{Colors.RED}{e}{Colors.RESET}")

    input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.RESET}")

def logs_screen(api: OrangModsAPI):
    print_header("📋 ЛОГИ")

    try:
        # Здесь можно добавить реальные логи из БД
        # Пока просто заглушка
        print(f"{Colors.DIM}  Логи можно посмотреть на Render.com в разделе Logs{Colors.RESET}")
        print(f"  {Colors.DIM}или через API /api/logs{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}{e}{Colors.RESET}")

    input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.RESET}")

# ============================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================

def main():
    clear()
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("  🍊 ORANGMODS ADMIN CLI")
    print(f"{Colors.RESET}")

    api = OrangModsAPI()

    # Если есть сохраненный токен - пробуем использовать
    if api.token:
        try:
            api.info()
            print(f"{Colors.GREEN}✅ Автоматический вход по сохраненному токену{Colors.RESET}")
            time.sleep(1)
            main_menu(api)
            return
        except:
            clear_token()
            api.token = None

    # Вход
    while True:
        if login_screen(api):
            main_menu(api)
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear()
        print(f"{Colors.GREEN}👋 До свидания!{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Ошибка: {e}{Colors.RESET}")
        sys.exit(1)
