import os
import re
import sys
import csv
import io
import json
import uuid
import time
import math
import random
import ctypes
import shutil
import string
import hashlib
import hmac
import datetime
import threading
import subprocess
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ==================== КОНСТАНТЫ ====================
APP_NAME = "SentryX"
APP_VERSION = "1.1.5 Beta"
APP_AUTHOR = "SentryX Security"

APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))
CONFIG_DIR = os.path.join(APPDATA, "SentryX")
ACCOUNTS_DIR = os.path.join(CONFIG_DIR, "accounts")
ACCOUNTS_FILE = os.path.join(CONFIG_DIR, "accounts.json")
CURRENT_USER_FILE = os.path.join(CONFIG_DIR, "current_user.txt")
GUEST_DIR = os.path.join(CONFIG_DIR, "guest")

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(ACCOUNTS_DIR, exist_ok=True)
os.makedirs(GUEST_DIR, exist_ok=True)

CONFIG_FILE = None
HISTORY_FILE = None
QUARANTINE_DIR = None
QUARANTINE_DB = None
PENDING_SCAN_FILE = None

UPDATE_MANIFEST_URL = "https://raw.githubusercontent.com/admins11/SentryX/main/version.json"
UPDATE_STATE_FILE = os.path.join(CONFIG_DIR, "update_state.json")

CREATE_NO_WINDOW = 0x08000000
_MUTEX_HANDLE = None

AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_VALUE = "SentryX"

GWL_EXSTYLE = -20
WS_EX_APPWINDOW = 0x00040000
WS_EX_TOOLWINDOW = 0x00000080


def _apply_user_paths(user_dir):
    global CONFIG_FILE, HISTORY_FILE, QUARANTINE_DB, QUARANTINE_DIR, PENDING_SCAN_FILE
    os.makedirs(user_dir, exist_ok=True)
    CONFIG_FILE = os.path.join(user_dir, "config.json")
    HISTORY_FILE = os.path.join(user_dir, "history.json")
    QUARANTINE_DB = os.path.join(user_dir, "quarantine.json")
    QUARANTINE_DIR = os.path.join(user_dir, "Quarantine")
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    PENDING_SCAN_FILE = os.path.join(user_dir, "pending_scan.txt")


def get_current_user():
    try:
        if os.path.exists(CURRENT_USER_FILE):
            with open(CURRENT_USER_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return ""


def set_current_user(name):
    try:
        if name:
            with open(CURRENT_USER_FILE, "w", encoding="utf-8") as f:
                f.write(name)
        else:
            if os.path.exists(CURRENT_USER_FILE):
                os.remove(CURRENT_USER_FILE)
    except Exception:
        pass


def _init_paths():
    user = get_current_user()
    ud = os.path.join(ACCOUNTS_DIR, user) if user else GUEST_DIR
    _apply_user_paths(ud)


def hash_password(pw):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def get_accounts():
    return load_json(ACCOUNTS_FILE, {"users": []}).get("users", [])


def save_accounts(users):
    save_json(ACCOUNTS_FILE, {"users": users})


def create_account(name, password):
    name = (name or "").strip()
    if len(name) < 2:
        return False, "Имя слишком короткое (мин. 2 символа)"
    if len(name) > 24:
        return False, "Имя слишком длинное (макс. 24)"
    for ch in name:
        if not (ch.isalnum() or ch in "_-"):
            return False, "Разрешены только буквы, цифры, _ и -"
    if len(password or "") < 3:
        return False, "Пароль слишком короткий (мин. 3 символа)"
    users = get_accounts()
    for u in users:
        if u["name"].lower() == name.lower():
            return False, "Такое имя уже существует"
    users.append({"name": name, "password_hash": hash_password(password),
                  "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    save_accounts(users)
    try:
        os.makedirs(os.path.join(ACCOUNTS_DIR, name), exist_ok=True)
    except Exception:
        pass
    return True, ""


def verify_login(name, password):
    for u in get_accounts():
        if u["name"].lower() == name.lower():
            return u["password_hash"] == hash_password(password)
    return False


def delete_account(name):
    users = [u for u in get_accounts() if u["name"].lower() != name.lower()]
    save_accounts(users)
    try:
        ud = os.path.join(ACCOUNTS_DIR, name)
        if os.path.isdir(ud):
            shutil.rmtree(ud, ignore_errors=True)
    except Exception:
        pass


def _get_launch_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    script = os.path.abspath(__file__)
    return f'"{_get_gui_python_executable()}" "{script}"'


def _get_gui_python_executable():
    """Return pythonw.exe for GUI launches when running from a source checkout."""
    if getattr(sys, "frozen", False):
        return sys.executable
    executable = os.path.abspath(sys.executable)
    if os.path.basename(executable).lower() == "python.exe":
        pythonw = os.path.join(os.path.dirname(executable), "pythonw.exe")
        if os.path.isfile(pythonw):
            return pythonw
    return executable


def _relaunch_without_console():
    """Move a source-script launch from python.exe to pythonw.exe."""
    if getattr(sys, "frozen", False):
        return False
    gui_python = _get_gui_python_executable()
    if os.path.normcase(gui_python) == os.path.normcase(os.path.abspath(sys.executable)):
        return False
    try:
        subprocess.Popen(
            [gui_python, os.path.abspath(__file__), *sys.argv[1:]],
            creationflags=CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            close_fds=True,
        )
        return True
    except Exception:
        return False


def is_autostart_installed():
    if not HAS_WINREG:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0,
                            winreg.KEY_READ) as k:
            try:
                val, _ = winreg.QueryValueEx(k, AUTOSTART_VALUE)
                return bool(val)
            except FileNotFoundError:
                return False
    except Exception:
        return False


def install_autostart():
    if not HAS_WINREG:
        return False
    try:
        cmd = _get_launch_command()
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY) as k:
            winreg.SetValueEx(k, AUTOSTART_VALUE, 0, winreg.REG_SZ, cmd)
        return True
    except Exception:
        return False


def uninstall_autostart():
    if not HAS_WINREG:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0,
                            winreg.KEY_ALL_ACCESS) as k:
            try:
                winreg.DeleteValue(k, AUTOSTART_VALUE)
            except FileNotFoundError:
                pass
        return True
    except Exception:
        return False


# ==================== IOC ====================
MINER_PROCESSES = {
    "xmrig", "xmrig-proxy", "xmrig-amd", "xmrig-nvidia", "xmr-stak",
    "xmr-stak-cpu", "xmr-stak-amd", "xmr-stak-nvidia",
    "nbminer", "nbm", "claymore", "claymoreminer", "ethminer", "ethminer-nv",
    "phoenixminer", "trex", "t-rex", "lolminer",
    "gminer", "teamredminer", "srbminer", "minerd", "cpuminer",
    "cgminer", "bfgminer", "cudaminer",
    "kryptex", "nanominer", "wildrig", "wildrig-miner", "progpowminer",
    "ccminer", "ewbf", "optiminer", "silentarmy", "eqminer",
    "nsfminer", "srbminer-multi", "xmr-stak-rx",
}

RAT_PROCESSES = {
    "njrat", "njw0rm", "quasar", "quasarrat", "darkcomet", "dcrat",
    "remcos", "remcosrat", "nanacore", "asyncrat", "orcus", "pandora",
    "pandorahvnc", "warzone", "warzonerat", "cybergate",
    "imminent", "blackshades", "adwind", "jsocket", "jsocketrat",
    "xtremerat", "bifrost", "poisonivy", "lostdoor", "spynet",
    "luminosity", "babylon", "venom", "venomrat",
}

STEALER_PROCESSES = {
    "agenttesla", "lokibot", "lokipws", "formbook", "formgrabber",
    "redline", "redlinestealer", "racoon", "raccoonstealer",
    "azorult", "vidar", "vidarstealer", "marsstealer",
    "predatorstealer", "recordbreaker", "aurorastealer", "kpot",
}

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 7777, 8888, 9999, 1337, 31337,
    14444, 14433, 45560, 45700, 12345, 54321, 33445,
}

SAFE_PROCESS_NAMES = {
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "vivaldi.exe", "iexplore.exe", "chromium.exe", "opera_gx.exe",
    "telegram.exe", "discord.exe", "slack.exe", "zoom.exe", "skype.exe",
    "teams.exe", "ms-teams.exe", "whatsapp.exe", "signal.exe", "viber.exe",
    "element.exe", "thunderbird.exe",
    "code.exe", "devenv.exe", "pycharm64.exe", "idea64.exe", "webstorm64.exe",
    "clion64.exe", "rider64.exe", "goland64.exe", "phpstorm64.exe",
    "sublime_text.exe", "notepad++.exe", "atom.exe", "vim.exe", "emacs.exe",
    "python.exe", "pythonw.exe", "python3.exe", "py.exe", "node.exe", "npm.exe",
    "git.exe", "git-bash.exe", "gcc.exe", "g++.exe", "clang.exe",
    "java.exe", "javaw.exe",
    "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "smss.exe", "wininit.exe", "taskhostw.exe", "dwm.exe",
    "spoolsv.exe", "searchindexer.exe", "runtimebroker.exe", "sihost.exe",
    "ctfmon.exe", "fontdrvhost.exe", "audiodg.exe", "conhost.exe", "dllhost.exe",
    "taskmgr.exe", "regedit.exe", "mmc.exe", "powershell.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "notepad.exe", "mspaint.exe", "calc.exe",
    "shellhost.exe", "startmenuexperiencehost.exe", "useroobebroker.exe",
    "applicationframehost.exe", "textinputhost.exe", "lockapp.exe",
    "backgroundtaskhost.exe", "systemsettings.exe", "smartscreen.exe",
    "securityhealthsystray.exe", "securityhealthservice.exe",
    "windefend.exe", "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe",
    "searchhost.exe", "widgetservice.exe", "widgets.exe",
    "steam.exe", "steamwebhelper.exe", "steamservice.exe",
    "epicgameslauncher.exe", "battle.net.exe",
    "riotclientservices.exe", "leagueclient.exe", "valorant.exe",
    "csgo.exe", "cs2.exe", "dota2.exe", "gta5.exe",
    "spotify.exe", "vlc.exe", "mpv.exe", "wmplayer.exe", "obs64.exe",
    "obs32.exe", "obs.exe", "audacity.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "msaccess.exe", "mspub.exe",
    "dropbox.exe", "onedrive.exe", "googledrivesync.exe", "megasync.exe",
    "yandexdisk.exe", "nextcloud.exe",
    "7zfm.exe", "winrar.exe", "bandizip.exe", "everything.exe",
    "sharex.exe", "greenshot.exe", "lightshot.exe",
    "nvidia share.exe", "nvcontainer.exe", "nvidia web helper.exe",
    "amdow.exe", "radeonsoftware.exe", "atiesrxx.exe", "atieclxx.exe",
    "rainmeter.exe", "translucenttb.exe", "powertoys.exe",
    "searchapp.exe", "yourphone.exe", "phoneexperiencehost.exe",
    "gamebar.exe", "gamebarftserver.exe", "gamebarpresencewriter.exe",
    "winstore.app.exe", "storeexperiencehost.exe",
    "acrord32.exe", "acrobat.exe",
    "photos.exe", "photosapp.exe", "microsoft.photos.exe",
    "setup.exe", "install.exe", "installer.exe", "update.exe", "updater.exe",
    "uninstall.exe", "unins000.exe", "unins001.exe",
    "nsis.exe", "innoextract.exe", "7zsetup.exe",
    "mumu-setup.exe", "mumu.exe", "mumuplayer.exe",
    "adbsetup.exe", "adb.exe",
    "python-3.exe", "python-setup.exe",
    "steamsetup.exe", "discordsetup.exe", "telegramsetup.exe",
    "vcredist_x64.exe", "vcredist_x86.exe",
    "directx_setup.exe", "dxsetup.exe",
    "nvidiasetup.exe", "geforcenow.exe",
    "epicgameslauncherinstaller.exe",
}

SAFE_FOLDERS = [
    "\\appdata\\local\\programs\\", "\\appdata\\local\\microsoft\\",
    "\\appdata\\local\\google\\", "\\appdata\\local\\yandex\\",
    "\\appdata\\local\\packages\\",
    "\\appdata\\roaming\\telegram desktop", "\\appdata\\roaming\\discord",
    "\\appdata\\roaming\\slack", "\\appdata\\roaming\\spotify",
    "\\appdata\\roaming\\zoom", "\\appdata\\roaming\\code",
    "\\appdata\\roaming\\microsoft\\", "\\appdata\\roaming\\steam",
    "\\appdata\\roaming\\vlc", "\\appdata\\roaming\\obs-studio",
    "\\program files\\", "\\program files (x86)\\",
    "\\windows\\system32\\", "\\windows\\syswow64\\",
    "\\windows\\winsxs\\", "\\windows\\microsoft.net\\",
    "\\windows\\assembly\\", "\\windows\\systemapps\\",
    "\\windows\\immersivecontrolpanel\\",
    "\\programdata\\microsoft\\", "\\programdata\\nvidia",
    "\\programdata\\amd", "\\programdata\\package cache\\",
    "\\programdata\\microsoft\\windows defender", "\\sentryx\\",
]


def is_safe_process(name, exe_path):
    if not name:
        return False
    nl = name.lower()
    if nl in SAFE_PROCESS_NAMES:
        return True
    if exe_path:
        el = exe_path.lower()
        for sf in SAFE_FOLDERS:
            if sf in el:
                return True
    return False


def try_acquire_single_instance():
    try:
        kernel32 = ctypes.windll.kernel32
        global _MUTEX_HANDLE
        _MUTEX_HANDLE = kernel32.CreateMutexW(
            None, False, "Global\\SentryX_SingleInstance_v141")
        return kernel32.GetLastError() != 183
    except Exception:
        return True


def send_path_to_running_instance(path):
    try:
        with open(PENDING_SCAN_FILE, "w", encoding="utf-8") as f:
            f.write(path)
        return True
    except Exception:
        return False


def read_pending_scan():
    try:
        if not PENDING_SCAN_FILE or not os.path.exists(PENDING_SCAN_FILE):
            return None
        with open(PENDING_SCAN_FILE, "r", encoding="utf-8") as f:
            path = f.read().strip()
        try:
            os.remove(PENDING_SCAN_FILE)
        except Exception:
            pass
        return path if path else None
    except Exception:
        return None


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


# ==================== АВТООБНОВЛЕНИЕ ====================
def parse_version(v):
    if not v:
        return (0, 0, 0)
    m = re.match(r"\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v))
    if not m:
        return (0, 0, 0)
    return tuple(int(x) if x else 0 for x in m.groups())


def is_newer_version(remote, local):
    return parse_version(remote) > parse_version(local)


def fetch_update_info(timeout=8):
    try:
        req = urllib.request.Request(
            UPDATE_MANIFEST_URL,
            headers={
                "User-Agent": f"SentryX/{APP_VERSION}",
                "Cache-Control": "no-cache",
            })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        if not isinstance(data, dict) or "version" not in data or "url" not in data:
            return None
        return data
    except Exception:
        return None


def download_file(url, dest, progress_cb=None, timeout=600):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": f"SentryX/{APP_VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            total = int(r.headers.get("Content-Length") or 0)
            done = 0
            chunk = 64 * 1024
            with open(dest, "wb") as f:
                while True:
                    block = r.read(chunk)
                    if not block:
                        break
                    f.write(block)
                    done += len(block)
                    if progress_cb:
                        try:
                            progress_cb(done, total)
                        except Exception:
                            pass
        return True, ""
    except Exception as e:
        return False, str(e)


def verify_sha256(file_path, expected_hex):
    if not expected_hex:
        return True, ""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        actual = h.hexdigest().lower()
        expected = str(expected_hex).strip().lower()
        if actual != expected:
            return False, (f"SHA256 не совпадает:\n"
                           f"получено:   {actual}\n"
                           f"ожидалось:  {expected}")
        return True, ""
    except Exception as e:
        return False, str(e)


def _get_running_target():
    if getattr(sys, "frozen", False):
        return os.path.abspath(sys.executable), True
    return os.path.abspath(__file__), False


def apply_update_and_restart(new_file_path):
    target, is_frozen = _get_running_target()
    launch = (f'"{target}"' if is_frozen
              else f'"{_get_gui_python_executable()}" "{target}"')
    bak = target + ".old"
    log_path = os.path.join(CONFIG_DIR, "update.log")
    tmp_bat = os.path.join(os.environ.get("TEMP", CONFIG_DIR),
                           f"sentryx_upd_{uuid.uuid4().hex}.bat")

    bat = f'''@echo off
chcp 65001 >nul
setlocal
echo [%date% %time%] Update start >> "{log_path}"
set RETRIES=60
:waitloop
move /y "{target}" "{bak}" >nul 2>&1
if not errorlevel 1 goto moved
set /a RETRIES-=1
if %RETRIES% leq 0 goto failed
timeout /t 1 /nobreak >nul
goto waitloop
:moved
echo [%date% %time%] Old file moved >> "{log_path}"
move /y "{new_file_path}" "{target}" >nul 2>&1
if errorlevel 1 (
    echo [%date% %time%] Install failed, restoring >> "{log_path}"
    move /y "{bak}" "{target}" >nul 2>&1
    goto failed
)
echo [%date% %time%] Installed >> "{log_path}"
start "" {launch}
timeout /t 2 /nobreak >nul
del /f /q "{bak}" >nul 2>&1
(goto) 2>nul & del "%~f0"
exit /b 0
:failed
echo [%date% %time%] FAILED >> "{log_path}"
move /y "{bak}" "{target}" >nul 2>&1
exit /b 1
'''
    try:
        with open(tmp_bat, "w", encoding="utf-8") as f:
            f.write(bat)
    except Exception as e:
        return False, f"Не удалось записать скрипт: {e}"

    try:
        DETACHED_PROCESS = 0x00000008
        subprocess.Popen(
            ["cmd", "/c", tmp_bat],
            creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
            close_fds=True)
        return True, ""
    except Exception as e:
        return False, str(e)


# ==================== ТЕМЫ ====================
THEMES = {
    "dark": {
        "BG": "#11161d", "BG_2": "#0c1117", "CARD": "#171e27", "CARD_2": "#202a35",
        "INPUT": "#101720", "BORDER": "#2a3542", "FG": "#e7edf2", "FG_DIM": "#91a0ad",
        "ACCENT": "#78aebe", "ACCENT_2": "#899bb2", "GREEN": "#78a88e",
        "RED": "#d47777", "YELLOW": "#d1ab69", "ON_ACCENT": "#0c1117",
        "GRADIENT_1": "#17212b", "GRADIENT_2": "#11161d", "TITLEBAR": "#0c1117",
    },
    "light": {
        "BG": "#f1f3f5", "BG_2": "#e8ecef", "CARD": "#ffffff", "CARD_2": "#f4f6f7",
        "INPUT": "#ffffff", "BORDER": "#d5dce1", "FG": "#202b34", "FG_DIM": "#697985",
        "ACCENT": "#3f7784", "ACCENT_2": "#637c91", "GREEN": "#4e8067",
        "RED": "#b95858", "YELLOW": "#9b762e", "ON_ACCENT": "#ffffff",
        "GRADIENT_1": "#dfe7eb", "GRADIENT_2": "#f1f3f5", "TITLEBAR": "#f8f9fa",
    },
}

VISUAL_SCENES = {
    "aurora": {"ACCENT": "#78aebe", "ACCENT_2": "#899bb2", "GREEN": "#78a88e",
               "START": "#1b3542", "END": "#182331", "GLOW": "#76aeb3"},
    "ocean": {"ACCENT": "#6ea8bc", "ACCENT_2": "#768fb0", "GREEN": "#6eaa98",
              "START": "#153d51", "END": "#172738", "GLOW": "#58a5c0"},
    "forest": {"ACCENT": "#82aa8b", "ACCENT_2": "#a1a77b", "GREEN": "#75a785",
               "START": "#203e34", "END": "#192a28", "GLOW": "#82b296"},
    "ember": {"ACCENT": "#cf8876", "ACCENT_2": "#ad8595", "GREEN": "#88a68a",
              "START": "#4a302b", "END": "#28232a", "GLOW": "#d69479"},
    "arctic": {"ACCENT": "#92b4c7", "ACCENT_2": "#9aa8c4", "GREEN": "#84b6a0",
               "START": "#263c50", "END": "#1c2735", "GLOW": "#a4c9d8"},
}

# Offline beta invite: the raw invite is shared separately with testers.
# This only grants local tester features; without a service it is not revocable.
TESTER_INVITE_SHA256 = "DE95846D3C95B0DB442D6DF9449877570492CDBCC87AC67A493A53FFC586C4CE"


def is_tester_invite(code):
    normalized = re.sub(r"[\s-]+", "", str(code).upper())
    if not normalized.isascii() or not normalized.isalnum():
        return False
    digest = hashlib.sha256(normalized.encode("ascii")).hexdigest().upper()
    return hmac.compare_digest(digest, TESTER_INVITE_SHA256)

TEXTS = {
    "ru": {
        "nav_home": "Главная", "nav_log": "Журнал", "nav_quarantine": "Карантин",
        "nav_repair": "Восстановление", "nav_settings": "Настройки",
        "nav_premium": "Тестерам", "nav_about": "О программе",
        "status_ready": "Готов к работе", "status_scanning": "Сканирование...",
        "status_stopping": "Останавливаю...", "status_done_clean": "Проверка завершена · чисто",
        "status_defender_missing": "Defender не найден", "btn_stop": "СТОП",
        "home_title": "Проверка системы",
        "home_sub": "Запусти сканирование через встроенный движок Windows Defender",
        "folder_label": "ПАПКА ДЛЯ ПРОВЕРКИ", "btn_browse": "ОБЗОР",
        "btn_folder": "Проверить папку", "btn_quick": "Быстрая проверка",
        "btn_full": "Полная проверка", "btn_file": "Проверить файл",
        "mini_engine_t": "ДВИЖОК", "mini_engine_v": "Windows Defender",
        "mini_speed_t": "СКОРОСТЬ", "mini_speed_v": "1–3 минуты",
        "mini_privacy_t": "ПРИВАТНОСТЬ", "mini_privacy_v": "без интернета",
        "mini_license_t": "ЛИЦЕНЗИЯ", "mini_license_v": "Free",
        "last_scan_title": "ПОСЛЕДНЯЯ ПРОВЕРКА", "last_scan_none": "Проверок ещё не было",
        "last_scan_threats": "Угроз: {n}", "last_scan_clean": "Чисто",
        "log_title": "Журнал", "log_sub": "Все действия сканера в реальном времени",
        "log_events": "СОБЫТИЯ",
        "log_search_ph": "🔍 Поиск по журналу...",
        "log_filter_all": "Все", "log_filter_info": "Инфо",
        "log_filter_warn": "Предупр.", "log_filter_err": "Ошибки",
        "log_filter_threat": "Угрозы",
        "log_empty": "Журнал пуст", "log_nothing_found": "Ничего не найдено по фильтру",
        "quar_title": "Карантин", "quar_sub": "Изолированные файлы",
        "quar_empty": "Карантин пуст", "quar_restore": "Восстановить",
        "quar_delete": "Удалить",
        "quar_confirm_delete": "Удалить файл навсегда?",
        "quar_confirm_restore": "Восстановить файл по исходному пути?",
        "quar_restored": "Файл восстановлен", "quar_deleted": "Файл удалён",
        "quar_added": "Файл добавлен в карантин",
        "quar_threat_q": "Обнаружена угроза!\n\nФайл: {name}\nПереместить в карантин?",
        "set_title": "Настройки", "set_sub": "Внешний вид, язык и обслуживание",
        "set_appear": "ВНЕШНИЙ ВИД", "set_theme": "Тема оформления",
        "set_theme_dark": "🌙  Тёмная", "set_theme_light": "☀  Светлая",
        "set_lang": "Язык интерфейса",
        "set_lang_ru": "🇷🇺  Русский", "set_lang_en": "🇬🇧  English",
        "set_account": "АККАУНТ", "set_acc_guest": "Вы работаете как гость",
        "set_acc_guest_hint": "Данные хранятся отдельно. Создайте аккаунт для сохранения нескольких профилей.",
        "set_acc_logged": "Вы вошли как: {name}",
        "set_acc_logged_hint": "Ваши настройки, история и карантин хранятся отдельно от других аккаунтов.",
        "set_acc_manage": "👤  Управление аккаунтом", "set_acc_logout": "🚪  Выйти",
        "set_integration": "ИНТЕГРАЦИЯ С WINDOWS",
        "set_ctx_menu": "Контекстное меню проводника",
        "set_ctx_install": "✅  Установить", "set_ctx_remove": "❌  Удалить",
        "set_ctx_hint": "Правый клик по файлу → «Проверить в SentryX»",
        "set_ctx_installed": "✅ Установлено",
        "set_autostart": "Автозапуск с Windows",
        "set_autostart_hint": "SentryX будет запускаться автоматически при включении ПК и работать в трее",
        "set_autostart_unavailable": "⚠ Недоступно (winreg не загружен)",
        "set_protection": "ЗАЩИТА И УВЕДОМЛЕНИЯ",
        "set_realtime": "Защита в реальном времени",
        "set_realtime_hint": "Следить за Defender, UAC и explorer.exe. Восстанавливать автоматически.",
        "set_auto_downloads": "Автопроверка Загрузок",
        "set_auto_downloads_hint": "Проверять новые файлы в папке Загрузки автоматически",
        "set_notifications": "Уведомления Windows",
        "set_notifications_hint": "Показывать уведомления о результатах проверок",
        "btn_on": "ВКЛ", "btn_off": "ВЫКЛ",
        "watchdog_missing": "⚠ Требуется pip install watchdog",
        "set_data": "ДАННЫЕ", "set_open_quar": "📂  Открыть карантин",
        "set_open_logs": "📂  Открыть папку данных",
        "set_clear_hist": "🗑  Очистить историю", "set_clear_hist_ok": "История очищена",
        "set_defender": "WINDOWS DEFENDER", "set_def_loading": "Загрузка...",
        "btn_refresh": "🔄  ОБНОВИТЬ СТАТУС", "btn_update_sigs": "⬇  ОБНОВИТЬ БАЗЫ",
        "pr_title": "\u0420\u0435\u0436\u0438\u043c \u0442\u0435\u0441\u0442\u0435\u0440\u0430", "pr_sub": "\u0411\u0435\u0441\u043f\u043b\u0430\u0442\u043d\u044b\u0439 \u0440\u0430\u043d\u043d\u0438\u0439 \u0434\u043e\u0441\u0442\u0443\u043f \u043a \u0444\u0443\u043d\u043a\u0446\u0438\u044f\u043c \u0438 \u043f\u043e\u043c\u043e\u0449\u044c \u0432 \u0440\u0430\u0437\u0432\u0438\u0442\u0438\u0438 SentryX",
        "pr_free": "FREE", "pr_tester": "TESTER",
        "pr_current": "\u2713 \u0410\u043a\u0442\u0438\u0432\u043d\u043e", "pr_buy": "\u0412\u0432\u0435\u0441\u0442\u0438 \u043a\u043e\u0434 \u0442\u0435\u0441\u0442\u0435\u0440\u0430",
        "pr_code_label": "\u0415\u0441\u0442\u044c \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u0435 \u0442\u0435\u0441\u0442\u0435\u0440\u0430?", "pr_code_btn": "\u0412\u0412\u0415\u0421\u0422\u0418 \u041a\u041e\u0414",
        "pr_dialog_title": "\u0414\u043e\u0441\u0442\u0443\u043f \u0442\u0435\u0441\u0442\u0435\u0440\u0430", "pr_dialog_hint": "\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043a\u043e\u0434 \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u044f:",
        "pr_demo_hint": "\u041a\u043e\u0434\u044b \u0432\u044b\u0434\u0430\u044e\u0442\u0441\u044f \u0443\u0447\u0430\u0441\u0442\u043d\u0438\u043a\u0430\u043c \u0431\u0435\u0442\u0430\u0442\u0435\u0441\u0442\u0430.",
        "pr_btn_activate": "\u0410\u043a\u0442\u0438\u0432\u0438\u0440\u043e\u0432\u0430\u0442\u044c", "pr_btn_cancel": "\u041e\u0442\u043c\u0435\u043d\u0430",
        "pr_code_wrong": "\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u043a\u043e\u0434 \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u044f", "pr_code_empty": "\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043a\u043e\u0434",
        "pr_activated_tester": "\u0414\u043e\u0441\u0442\u0443\u043f \u0442\u0435\u0441\u0442\u0435\u0440\u0430 \u0430\u043a\u0442\u0438\u0432\u0438\u0440\u043e\u0432\u0430\u043d!",
        "ab_title": "О программе", "ab_sub": "Информация о приложении",
        "ab_author": "АВТОР", "ab_features": "ОСОБЕННОСТИ",
        "splash_loading": "Загрузка...",
        "welcome_log": "👋 Добро пожаловать в SentryX",
        "welcome_author": "Автор: @ SМаруф 2026",
        "def_found": "✅ Windows Defender найден",
        "def_not_found": "❌ Windows Defender не найден",
        "scan_launch": "🛡  Запуск проверки: {label}",
        "scan_wait": "⏳ Это может занять время. Не закрывай окно.",
        "scan_clean": "✅ Угроз не найдено. Система чиста!",
        "scan_threats": "🚨 ОБНАРУЖЕНО УГРОЗ: {n}",
        "scan_result": "▸ ИТОГ: угроз не обнаружено",
        "scan_result_threats": "▸ ИТОГ: найдено угроз — {n}",
        "scan_counter": "Проверено: {cur} / {total}",
        "scan_counter_files": "Проверено: {cur}", "scan_elapsed": "Прошло: {t}",
        "ask_full_title": "Полная проверка",
        "ask_full_text": "Полная проверка может занять\nот 30 минут до 2 часов.\n\nПродолжить?",
        "ask_close": "Сканирование идёт. Выйти?",
        "err_folder": "Папка не найдена", "err_title": "Ошибка",
        "msg_wait": "Подожди", "msg_wait_text": "Дождись окончания сканирования",
        "upd_start": "⬇  Обновление баз Defender...",
        "upd_time": "   Это может занять 1–5 минут",
        "upd_ok": "✅ Базы обновлены", "upd_err": "❌ Ошибка обновления",
        "label_folder": "папки", "label_quick": "быстрой", "label_full": "полной",
        "label_file": "файла", "label_auto": "Автопроверка",
        "tray_hint": "SentryX свёрнут в трей.\nНажми на иконку возле часов.",
        "tray_open": "Открыть SentryX", "tray_scan": "Сканировать ПК",
        "tray_exit": "Выход", "tray_tooltip": "SentryX — защита активна",
        "hist_stopped": "Прервано",
        "notify_title": "SentryX", "notify_scan_done": "Проверка завершена",
        "notify_clean": "Угроз не найдено ✅",
        "notify_threats": "⚠ Обнаружено угроз: {n}",
        "notify_auto_start": "🔍 Автопроверка",
        "notify_auto_file": "Проверяю: {name}",
        "notify_auto_threat": "⚠ УГРОЗА в загрузке!\n{name}",
        "notify_auto_clean": "✅ Файл чист: {name}",
        "prot_defender_off": "⚠ Defender отключён! Пытаюсь включить...",
        "prot_defender_on": "✅ Defender восстановлен",
        "prot_defender_fail": "❌ Не удалось включить Defender",
        "prot_uac_off": "⚠ UAC отключён! Восстанавливаю...",
        "prot_uac_on": "✅ UAC восстановлен",
        "prot_uac_fail": "❌ Не удалось включить UAC (нужен админ)",
        "prot_explorer_off": "⚠ explorer.exe не найден! Запускаю...",
        "prot_explorer_on": "✅ explorer.exe перезапущен",
        "prot_explorer_fail": "❌ Не удалось перезапустить explorer.exe",
        "prot_started": "🛡  Защита в реальном времени активна",
        "prot_stopped": "🛡  Защита в реальном времени остановлена",
        "prot_enabled_log": "🛡  Монитор защиты: Defender · UAC · explorer.exe",
        "acc_title": "Аккаунт", "acc_sub": "Локальные профили SentryX",
        "acc_tab_login": "Вход", "acc_tab_register": "Регистрация",
        "acc_name": "Имя пользователя", "acc_password": "Пароль",
        "acc_password2": "Повторите пароль",
        "acc_btn_login": "Войти", "acc_btn_register": "Создать",
        "acc_btn_cancel": "Отмена", "acc_btn_delete": "Удалить аккаунт",
        "acc_btn_logout": "Выйти",
        "acc_you": "Вы вошли как: {name}", "acc_guest": "Гость",
        "acc_existing": "Существующие аккаунты:", "acc_none": "аккаунтов пока нет",
        "acc_wrong_pw": "Неверное имя или пароль",
        "acc_created": "Аккаунт создан и активирован!\nПриложение перезапустится.",
        "acc_deleted": "Аккаунт удалён. Приложение перезапустится.",
        "acc_logged_in": "Вы вошли. Приложение перезапустится.",
        "acc_logged_out": "Вы вышли как гость. Приложение перезапустится.",
        "acc_confirm_delete": "Удалить аккаунт «{name}»?\nВсе данные будут потеряны навсегда.",
        "acc_confirm_logout": "Выйти из аккаунта?",
        "acc_pw_mismatch": "Пароли не совпадают",
        "sched_category": "Планировщик",
        "sched_delete_task": "🚫 Удалить задачу",
        "sched_confirm": "Удалить задачу планировщика?\n\n{name}",
        "sched_deleted": "Задача удалена",
        "autostart_ok": "Автозапуск включён",
        "autostart_off": "Автозапуск выключен",
        "autostart_err": "Не удалось изменить автозапуск",
        "upd_title": "Доступно обновление",
        "upd_sub": "Вышла новая версия SentryX",
        "upd_current": "ТЕКУЩАЯ",
        "upd_whatsnew": "ЧТО НОВОГО",
        "upd_no_notes": "Описание изменений не указано.",
        "upd_mandatory": "ОБЯЗАТЕЛЬНО",
        "upd_mandatory_warn": "Это обязательное обновление.\nПропустить его?",
        "upd_btn_update": "⬇  Обновить сейчас",
        "upd_btn_later": "Позже",
        "upd_downloading": "Загрузка обновления...",
        "upd_installing": "Установка... приложение перезапустится",
        "upd_failed": "Ошибка обновления",
        "upd_check_title": "Обновления",
        "upd_check_fail": "Не удалось проверить обновления.\nПроверьте подключение к интернету.",
        "upd_check_latest": "У вас последняя версия: v{v}",
        "upd_check_btn": "🔎  Проверить обновления",
        "upd_checking": "Проверяю обновления...",
        "upd_section": "ОБНОВЛЕНИЯ",
        "upd_auto_check": "Проверять обновления при запуске",
        "upd_auto_check_hint": "Автоматически искать новые версии SentryX в интернете",
        "upd_last_check": "Последняя проверка: {t}",
        "upd_never_checked": "проверок ещё не было",
        "upd_sha_ok": "✅ Целостность файла подтверждена",
        "upd_sha_fail": "❌ Файл повреждён или подменён",
    },
    "en": {
        "nav_home": "Home", "nav_log": "Log", "nav_quarantine": "Quarantine",
        "nav_repair": "Repair", "nav_settings": "Settings",
        "nav_premium": "Tester", "nav_about": "About",
        "status_ready": "Ready", "status_scanning": "Scanning...",
        "status_stopping": "Stopping...", "status_done_clean": "Scan complete · clean",
        "status_defender_missing": "Defender not found", "btn_stop": "STOP",
        "home_title": "System scan",
        "home_sub": "Run a scan using the built-in Windows Defender engine",
        "folder_label": "FOLDER TO SCAN", "btn_browse": "BROWSE",
        "btn_folder": "Scan folder", "btn_quick": "Quick scan",
        "btn_full": "Full scan", "btn_file": "Scan file",
        "mini_engine_t": "ENGINE", "mini_engine_v": "Windows Defender",
        "mini_speed_t": "SPEED", "mini_speed_v": "1–3 min",
        "mini_privacy_t": "PRIVACY", "mini_privacy_v": "offline",
        "mini_license_t": "LICENSE", "mini_license_v": "Free",
        "last_scan_title": "LAST SCAN", "last_scan_none": "No scans yet",
        "last_scan_threats": "Threats: {n}", "last_scan_clean": "Clean",
        "log_title": "Log", "log_sub": "All scanner actions in real time",
        "log_events": "EVENTS",
        "log_search_ph": "🔍 Search log...",
        "log_filter_all": "All", "log_filter_info": "Info",
        "log_filter_warn": "Warnings", "log_filter_err": "Errors",
        "log_filter_threat": "Threats",
        "log_empty": "Log is empty", "log_nothing_found": "Nothing found by filter",
        "quar_title": "Quarantine", "quar_sub": "Isolated files",
        "quar_empty": "Quarantine is empty", "quar_restore": "Restore",
        "quar_delete": "Delete",
        "quar_confirm_delete": "Delete file permanently?",
        "quar_confirm_restore": "Restore file to original path?",
        "quar_restored": "File restored", "quar_deleted": "File deleted",
        "quar_added": "File quarantined",
        "quar_threat_q": "Threat detected!\n\nFile: {name}\nMove to quarantine?",
        "set_title": "Settings", "set_sub": "Appearance, language and maintenance",
        "set_appear": "APPEARANCE", "set_theme": "Theme",
        "set_theme_dark": "🌙  Dark", "set_theme_light": "☀  Light",
        "set_lang": "Interface language",
        "set_lang_ru": "🇷🇺  Russian", "set_lang_en": "🇬🇧  English",
        "set_account": "ACCOUNT", "set_acc_guest": "You are working as guest",
        "set_acc_guest_hint": "Data is stored separately. Create an account to save multiple profiles.",
        "set_acc_logged": "You are logged in as: {name}",
        "set_acc_logged_hint": "Your settings, history and quarantine are separate from other accounts.",
        "set_acc_manage": "👤  Manage account", "set_acc_logout": "🚪  Log out",
        "set_integration": "WINDOWS INTEGRATION",
        "set_ctx_menu": "Explorer context menu",
        "set_ctx_install": "✅  Install", "set_ctx_remove": "❌  Remove",
        "set_ctx_hint": "Right-click a file → \"Scan with SentryX\"",
        "set_ctx_installed": "✅ Installed",
        "set_autostart": "Start with Windows",
        "set_autostart_hint": "SentryX will launch automatically on PC boot and run in tray",
        "set_autostart_unavailable": "⚠ Unavailable (winreg not loaded)",
        "set_protection": "PROTECTION & NOTIFICATIONS",
        "set_realtime": "Real-time protection",
        "set_realtime_hint": "Watch Defender, UAC and explorer.exe. Auto-restore them.",
        "set_auto_downloads": "Auto-scan Downloads",
        "set_auto_downloads_hint": "Automatically scan new files in Downloads folder",
        "set_notifications": "Windows notifications",
        "set_notifications_hint": "Show notifications about scan results",
        "btn_on": "ON", "btn_off": "OFF",
        "watchdog_missing": "⚠ Requires pip install watchdog",
        "set_data": "DATA", "set_open_quar": "📂  Open quarantine",
        "set_open_logs": "📂  Open data folder",
        "set_clear_hist": "🗑  Clear history", "set_clear_hist_ok": "History cleared",
        "set_defender": "WINDOWS DEFENDER", "set_def_loading": "Loading...",
        "btn_refresh": "🔄  REFRESH STATUS", "btn_update_sigs": "⬇  UPDATE SIGNATURES",
        "pr_title": "Tester access", "pr_sub": "Free early access and a way to help improve SentryX",
        "pr_free": "FREE", "pr_tester": "TESTER",
        "pr_current": "✓ Active", "pr_buy": "Enter tester code",
        "pr_code_label": "Have a tester invite?", "pr_code_btn": "ENTER INVITE CODE",
        "pr_dialog_title": "Tester access", "pr_dialog_hint": "Enter your invite code:",
        "pr_demo_hint": "Invite codes are shared with selected beta testers.",
        "pr_btn_activate": "Activate", "pr_btn_cancel": "Cancel",
        "pr_code_wrong": "Invalid activation code", "pr_code_empty": "Enter code",
        "pr_activated_tester": "Tester access activated!",
        "ab_title": "About", "ab_sub": "Application information",
        "ab_author": "AUTHOR", "ab_features": "FEATURES",
        "splash_loading": "Loading...",
        "welcome_log": "👋 Welcome to SentryX",
        "welcome_author": "Author: @ Маруф 2026",
        "def_found": "✅ Windows Defender found",
        "def_not_found": "❌ Windows Defender not found",
        "scan_launch": "🛡  Starting scan: {label}",
        "scan_wait": "⏳ This may take a while. Don't close the window.",
        "scan_clean": "✅ No threats found. System is clean!",
        "scan_threats": "🚨 THREATS FOUND: {n}",
        "scan_result": "▸ RESULT: no threats",
        "scan_result_threats": "▸ RESULT: threats found — {n}",
        "scan_counter": "Scanned: {cur} / {total}",
        "scan_counter_files": "Scanned: {cur}", "scan_elapsed": "Elapsed: {t}",
        "ask_full_title": "Full scan",
        "ask_full_text": "A full PC scan can take\nfrom 30 min to 2 hours.\n\nContinue?",
        "ask_close": "Scanning in progress. Exit?",
        "err_folder": "Folder not found", "err_title": "Error",
        "msg_wait": "Wait", "msg_wait_text": "Wait for the current scan to finish",
        "upd_start": "⬇  Updating Defender signatures...",
        "upd_time": "   This may take 1–5 minutes",
        "upd_ok": "✅ Signatures updated", "upd_err": "❌ Update error",
        "label_folder": "folder", "label_quick": "quick", "label_full": "full",
        "label_file": "file", "label_auto": "Auto-scan",
        "tray_hint": "SentryX minimized to tray.\nClick the icon near the clock.",
        "tray_open": "Open SentryX", "tray_scan": "Scan PC",
        "tray_exit": "Exit", "tray_tooltip": "SentryX — protection active",
        "hist_stopped": "Stopped",
        "notify_title": "SentryX", "notify_scan_done": "Scan complete",
        "notify_clean": "No threats found ✅",
        "notify_threats": "⚠ Threats found: {n}",
        "notify_auto_start": "🔍 Auto-scan",
        "notify_auto_file": "Scanning: {name}",
        "notify_auto_threat": "⚠ THREAT in downloads!\n{name}",
        "notify_auto_clean": "✅ File is clean: {name}",
        "prot_defender_off": "⚠ Defender disabled! Trying to enable...",
        "prot_defender_on": "✅ Defender restored",
        "prot_defender_fail": "❌ Failed to enable Defender",
        "prot_uac_off": "⚠ UAC disabled! Restoring...",
        "prot_uac_on": "✅ UAC restored",
        "prot_uac_fail": "❌ Failed to enable UAC (admin required)",
        "prot_explorer_off": "⚠ explorer.exe not found! Starting...",
        "prot_explorer_on": "✅ explorer.exe restarted",
        "prot_explorer_fail": "❌ Failed to restart explorer.exe",
        "prot_started": "🛡  Real-time protection active",
        "prot_stopped": "🛡  Real-time protection stopped",
        "prot_enabled_log": "🛡  Protection monitor: Defender · UAC · explorer.exe",
        "acc_title": "Account", "acc_sub": "Local SentryX profiles",
        "acc_tab_login": "Login", "acc_tab_register": "Register",
        "acc_name": "Username", "acc_password": "Password",
        "acc_password2": "Repeat password",
        "acc_btn_login": "Log in", "acc_btn_register": "Create",
        "acc_btn_cancel": "Cancel", "acc_btn_delete": "Delete account",
        "acc_btn_logout": "Log out",
        "acc_you": "Logged in as: {name}", "acc_guest": "Guest",
        "acc_existing": "Existing accounts:", "acc_none": "no accounts yet",
        "acc_wrong_pw": "Invalid username or password",
        "acc_created": "Account created and activated!\nThe app will restart.",
        "acc_deleted": "Account deleted. The app will restart.",
        "acc_logged_in": "Logged in. The app will restart.",
        "acc_logged_out": "Logged out as guest. The app will restart.",
        "acc_confirm_delete": "Delete account \"{name}\"?\nAll data will be lost forever.",
        "acc_confirm_logout": "Log out of account?",
        "acc_pw_mismatch": "Passwords do not match",
        "sched_category": "Scheduler",
        "sched_delete_task": "🚫 Delete task",
        "sched_confirm": "Delete scheduled task?\n\n{name}",
        "sched_deleted": "Task deleted",
        "autostart_ok": "Autostart enabled",
        "autostart_off": "Autostart disabled",
        "autostart_err": "Failed to change autostart",
        "upd_title": "Update available",
        "upd_sub": "A new version of SentryX is available",
        "upd_current": "CURRENT",
        "upd_whatsnew": "WHAT'S NEW",
        "upd_no_notes": "No changelog provided.",
        "upd_mandatory": "MANDATORY",
        "upd_mandatory_warn": "This is a mandatory update.\nSkip it?",
        "upd_btn_update": "⬇  Update now",
        "upd_btn_later": "Later",
        "upd_downloading": "Downloading update...",
        "upd_installing": "Installing... the app will restart",
        "upd_failed": "Update failed",
        "upd_check_title": "Updates",
        "upd_check_fail": "Failed to check for updates.\nCheck your internet connection.",
        "upd_check_latest": "You have the latest version: v{v}",
        "upd_check_btn": "🔎  Check for updates",
        "upd_checking": "Checking for updates...",
        "upd_section": "UPDATES",
        "upd_auto_check": "Check for updates on startup",
        "upd_auto_check_hint": "Automatically look for new SentryX versions online",
        "upd_last_check": "Last check: {t}",
        "upd_never_checked": "no checks yet",
        "upd_sha_ok": "✅ File integrity verified",
        "upd_sha_fail": "❌ File is corrupted or tampered",
    },
}


# ==================== МОНИТОР ЗАЩИТЫ ====================
class ProtectionMonitor:
    """
    Бесконечно следит за Defender / UAC / explorer.exe.
    Пробует восстановить при каждом обнаружении проблемы.
    Никаких "один раз и забыл" — работает непрерывно.
    """
    def __init__(self, app):
        self.app = app
        self._stop_evt = threading.Event()
        self._thread = None
        self.running = False
        self.defender_state = {"av": None, "rt": None, "tamper": False}
        self.uac_enabled = None
        self.explorer_ok = True
        self._first_run = True
        self.tick = 5            # Faster checks catch repeat Defender changes sooner.
        self.explorer_tick = 2   # цикл для explorer
        self._last_defender_attempt = 0.0
        self._last_uac_attempt = 0.0
        self._last_explorer_attempt = 0.0
        self._tamper_warned = False
        self._explorer_check_count = 0
        # флаги "мы уже знаем, что проблема есть, не спамим лог"
        self._defender_state_logged = "unknown"
        self._uac_state_logged = "unknown"
        self._explorer_state_logged = "unknown"

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self.running = True
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        self.running = False
        self._thread = None

    def _loop(self):
        # первая проверка через 2 сек
        self._stop_evt.wait(2)
        try:
            self._check_explorer()
            self._check_uac()
            self._check_defender()
        except Exception:
            pass
        self._first_run = False

        last_uac_def = time.time()
        last_explorer = time.time()

        while not self._stop_evt.is_set():
            now = time.time()
            if now - last_explorer >= self.explorer_tick:
                last_explorer = now
                try:
                    self._check_explorer()
                except Exception:
                    pass
            if now - last_uac_def >= self.tick:
                last_uac_def = now
                try:
                    self._check_uac()
                    self._check_defender()
                except Exception:
                    pass
            self._stop_evt.wait(1.0)
        self.running = False

    def _safe_notify(self, title, message):
        try:
            if hasattr(self.app, "_notify"):
                self.app.root.after(0, lambda: self.app._notify(title, message))
        except Exception:
            pass

    def _safe_log(self, text, tag="warn"):
        try:
            if hasattr(self.app, "_log"):
                self.app.root.after(0, lambda: self.app._log(text, tag))
        except Exception:
            pass

    # ---------- Defender ----------
    def _check_defender(self):
        try:
            ps = ("$s = Get-MpComputerStatus; "
                  "'AV=' + $s.AntivirusEnabled + ';' + "
                  "'RT=' + $s.RealTimeProtectionEnabled + ';' + "
                  "'TP=' + $s.IsTamperProtected")
            rc, out, err = _run_hidden(
                ["powershell", "-NoProfile", "-Command", ps],
                timeout=20, encoding="utf-8")
            if rc != 0 or not out:
                return
            parts = dict(p.split("=") for p in out.strip().split(";") if "=" in p)
            av = parts.get("AV", "").strip().lower() == "true"
            rt = parts.get("RT", "").strip().lower() == "true"
            tp = parts.get("TP", "").strip().lower() == "true"
            self.defender_state = {"av": av, "rt": rt, "tamper": tp}

            if tp and not self._tamper_warned:
                self._tamper_warned = True
                self._safe_log(
                    "⚠ Защита от подделки (Tamper Protection) включена. "
                    "Она блокирует программное включение Defender. "
                    "Отключи её в Безопасности Windows вручную.", "warn")

            if not self._first_run and (not av or not rt):
                self._on_defender_off()
            if av and rt:
                if self._defender_state_logged != "on":
                    self._defender_state_logged = "on"
                    if not self._first_run:
                        self._safe_log(self.app.T["prot_defender_on"], "ok")
        except Exception:
            pass

    def _on_defender_off(self):
        # Логируем один раз (переходное состояние)
        first_time = (self._defender_state_logged != "off")
        if first_time:
            self._defender_state_logged = "off"
            self._safe_log(self.app.T["prot_defender_off"], "warn")
            self._safe_notify("SentryX", self.app.T["prot_defender_off"])

        # Пробуем восстановить не чаще, чем раз в 15 секунд
        now = time.time()
        if now - self._last_defender_attempt < 5:
            return
        self._last_defender_attempt = now

        ok = self._try_enable_defender()
        if ok:
            self._defender_state_logged = "on"
            self._safe_log(self.app.T["prot_defender_on"], "ok")
        else:
            # Показываем ошибку только при первой попытке
            if first_time:
                if self.defender_state.get("tamper"):
                    self._safe_log(
                        "❌ Не удалось. Tamper Protection блокирует. "
                        "Отключи «Защита от подделки» в Безопасности Windows.",
                        "err")
                elif not is_admin():
                    self._safe_log(
                        "❌ Не удалось включить Defender (нужен админ)", "err")
                else:
                    self._safe_log(self.app.T["prot_defender_fail"], "err")

    def _try_enable_defender(self):
        if not is_admin():
            return False
        if self.defender_state.get("tamper"):
            return False

        if HAS_WINREG:
            for hive, path in [
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Microsoft\Windows Defender"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"),
            ]:
                try:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS) as k:
                        i = 0
                        names = []
                        try:
                            while True:
                                try:
                                    name, _, _ = winreg.EnumValue(k, i)
                                    names.append(name)
                                    i += 1
                                except OSError:
                                    break
                        except Exception:
                            pass
                        for name in names:
                            try:
                                winreg.DeleteValue(k, name)
                            except Exception:
                                pass
                except Exception:
                    pass

        try:
            ps = ("Set-MpPreference -DisableRealtimeMonitoring $false "
                  "-ErrorAction SilentlyContinue; "
                  "Set-MpPreference -DisableBehaviorMonitoring $false "
                  "-ErrorAction SilentlyContinue; "
                  "Set-MpPreference -DisableIOAVProtection $false "
                  "-ErrorAction SilentlyContinue; "
                  "Set-MpPreference -DisableScriptScanning $false "
                  "-ErrorAction SilentlyContinue; "
                  "Start-Service -Name WinDefend -ErrorAction SilentlyContinue; "
                  "Start-Service -Name WdNisSvc -ErrorAction SilentlyContinue; "
                  "Start-Service -Name Sense -ErrorAction SilentlyContinue")
            _run_hidden(["powershell", "-NoProfile", "-Command", ps],
                        timeout=60, encoding="utf-8")
        except Exception:
            pass

        time.sleep(2)
        try:
            ps = ("$s = Get-MpComputerStatus; "
                  "'AV=' + $s.AntivirusEnabled + ';' + "
                  "'RT=' + $s.RealTimeProtectionEnabled")
            rc, out, err = _run_hidden(
                ["powershell", "-NoProfile", "-Command", ps],
                timeout=15, encoding="utf-8")
            if rc == 0 and out:
                parts = dict(p.split("=") for p in out.strip().split(";") if "=" in p)
                av = parts.get("AV", "").strip().lower() == "true"
                rt = parts.get("RT", "").strip().lower() == "true"
                return av and rt
        except Exception:
            pass
        return False

    # ---------- UAC ----------
    def _check_uac(self):
        if not HAS_WINREG:
            return
        try:
            with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    0, winreg.KEY_READ) as k:
                val, _ = winreg.QueryValueEx(k, "EnableLUA")
            enabled = (val == 1)
            self.uac_enabled = enabled
            if not self._first_run and not enabled:
                self._on_uac_off()
            if enabled:
                if self._uac_state_logged != "on":
                    self._uac_state_logged = "on"
                    if not self._first_run:
                        self._safe_log(self.app.T["prot_uac_on"], "ok")
        except Exception:
            pass

    def _on_uac_off(self):
        first_time = (self._uac_state_logged != "off")
        if first_time:
            self._uac_state_logged = "off"
            self._safe_log(self.app.T["prot_uac_off"], "warn")
            self._safe_notify("SentryX", self.app.T["prot_uac_off"])

        now = time.time()
        if now - self._last_uac_attempt < 15:
            return
        self._last_uac_attempt = now

        ok = self._try_enable_uac()
        if ok:
            self._uac_state_logged = "on"
            self._safe_log(self.app.T["prot_uac_on"], "ok")
        else:
            if first_time:
                self._safe_log(self.app.T["prot_uac_fail"], "err")

    def _try_enable_uac(self):
        if not is_admin() or not HAS_WINREG:
            return False
        try:
            with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "EnableLUA", 0, winreg.REG_DWORD, 1)
            return True
        except Exception:
            return False

    # ---------- explorer ----------
    def _count_explorer_processes(self):
        count = 0
        if HAS_PSUTIL:
            try:
                for p in psutil.process_iter(attrs=["name"]):
                    try:
                        if (p.info.get("name") or "").lower() == "explorer.exe":
                            count += 1
                    except Exception:
                        continue
            except Exception:
                pass
        else:
            try:
                rc, out, err = _run_hidden(
                    ["tasklist", "/FI", "IMAGENAME eq explorer.exe", "/NH"],
                    timeout=5, encoding="cp866")
                for line in (out or "").splitlines():
                    if "explorer.exe" in line.lower():
                        count += 1
            except Exception:
                pass
        return count

    def _check_explorer(self):
        self._explorer_check_count += 1
        count = self._count_explorer_processes()

        # File-manager windows can keep explorer.exe alive after the Windows
        # shell (desktop/taskbar) has stopped.
        try:
            shell_running = bool(
                ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None))
        except Exception:
            shell_running = count > 0

        # Отладка раз в минуту
        if self._explorer_check_count % 30 == 0:
            self._safe_log(
                f"👁  Проверка explorer.exe: найдено процессов {count}",
                "dim")

        running = count > 0 and shell_running
        self.explorer_ok = running

        if not running:
            self._on_explorer_off()
        else:
            if self._explorer_state_logged != "on":
                self._explorer_state_logged = "on"
                if not self._first_run:
                    self._safe_log(self.app.T["prot_explorer_on"], "ok")

    def _on_explorer_off(self):
        first_time = (self._explorer_state_logged != "off")
        if first_time:
            self._explorer_state_logged = "off"
            self._safe_log(self.app.T["prot_explorer_off"], "warn")
            self._safe_notify("SentryX", self.app.T["prot_explorer_off"])

        now = time.time()
        if now - self._last_explorer_attempt < 2:
            return
        self._last_explorer_attempt = now

        ok = self._try_restart_explorer()
        if ok:
            self._explorer_state_logged = "on"
            self._safe_log(self.app.T["prot_explorer_on"], "ok")

    def _try_restart_explorer(self):
        # 1) start explorer.exe (в контексте пользователя)
        try:
            subprocess.Popen("start explorer.exe", shell=True,
                             creationflags=CREATE_NO_WINDOW)
            time.sleep(1)
            if self._count_explorer_processes() > 0:
                return True
        except Exception:
            pass

        # 2) explorer.exe напрямую
        try:
            subprocess.Popen(["explorer.exe"],
                             creationflags=CREATE_NO_WINDOW, close_fds=True)
            time.sleep(1)
            if self._count_explorer_processes() > 0:
                return True
        except Exception:
            pass

        # 3) cmd /c start "" explorer.exe
        try:
            subprocess.Popen(
                ["cmd", "/c", "start", "", "explorer.exe"],
                creationflags=CREATE_NO_WINDOW)
            time.sleep(1)
            if self._count_explorer_processes() > 0:
                return True
        except Exception:
            pass

        return False


def find_defender_exe():
    candidates = [
        r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe",
    ]
    pd = r"C:\ProgramData\Microsoft\Windows Defender\Platform"
    if os.path.isdir(pd):
        for d in sorted(os.listdir(pd), reverse=True):
            p = os.path.join(pd, d, "MpCmdRun.exe")
            if os.path.isfile(p):
                candidates.insert(0, p)
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


DEFENDER_EXE = find_defender_exe()


def _run_hidden(cmd, timeout=600, encoding="cp866"):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding=encoding, errors="replace",
                           timeout=timeout, creationflags=CREATE_NO_WINDOW)
        return (r.returncode, r.stdout or "", r.stderr or "")
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except Exception as e:
        return (-1, "", str(e))


def run_defender_scan(scan_type, target=None):
    if not DEFENDER_EXE:
        return (-1, "", "MpCmdRun.exe not found")
    cmd = [DEFENDER_EXE, "-Scan", "-ScanType", str(scan_type)]
    if scan_type == 3 and target:
        cmd += ["-File", target]
    return _run_hidden(cmd, timeout=7200)


def update_defender_signatures():
    if not DEFENDER_EXE:
        return (-1, "", "not found")
    return _run_hidden([DEFENDER_EXE, "-SignatureUpdate"], timeout=600)


def get_defender_status():
    try:
        ps = ("$s = Get-MpComputerStatus; "
              "'AV=' + $s.AntivirusEnabled + ';"
              "RT=' + $s.RealTimeProtectionEnabled + ';"
              "SigAge=' + $s.AntivirusSignatureAge + ';"
              "SigVer=' + $s.AntivirusSignatureVersion")
        rc, out, err = _run_hidden(["powershell", "-NoProfile", "-Command", ps],
                                    timeout=20, encoding="utf-8")
        return (out or "").strip()
    except Exception:
        return ""


def make_tray_image():
    img = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((4, 4, 124, 124), fill=(23, 30, 39, 255),
              outline=(120, 174, 190, 255), width=4)
    shield = [(64, 20), (94, 32), (91, 67), (64, 102), (37, 67), (34, 32)]
    d.polygon(shield, fill=(120, 174, 190, 255))
    d.line([(49, 59), (61, 72), (81, 49)], fill=(12, 17, 23, 255),
           width=7, joint="curve")
    resampling = getattr(Image, "Resampling", Image)
    return img.resize((64, 64), resampling.LANCZOS)


def _get_process_list():
    processes = []
    if HAS_PSUTIL:
        try:
            for p in psutil.process_iter(attrs=["pid", "name", "exe"]):
                try:
                    info = p.info
                    processes.append({"pid": info.get("pid"),
                                      "name": info.get("name") or "",
                                      "exe": info.get("exe") or ""})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
    else:
        try:
            rc, out, err = _run_hidden(["tasklist", "/FO", "CSV", "/NH"],
                                        timeout=20, encoding="cp866")
            for line in (out or "").split("\n"):
                parts = [p.strip('"') for p in line.strip().split('","')]
                if len(parts) >= 2 and parts[0]:
                    processes.append({"pid": int(parts[1]) if parts[1].isdigit() else 0,
                                      "name": parts[0], "exe": ""})
        except Exception:
            pass
    return processes


def _get_startup_entries():
    entries = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    ] if HAS_WINREG else []
    for root, path, label in keys:
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        entries.append({"source": f"Реестр: {label}",
                                        "name": name, "value": value})
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
    sf = [
        os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for folder in sf:
        if os.path.isdir(folder):
            try:
                for f in os.listdir(folder):
                    entries.append({"source": "Папка Startup", "name": f,
                                    "value": os.path.join(folder, f)})
            except Exception:
                pass
    return entries


def _get_network_connections():
    conns = []
    if HAS_PSUTIL:
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status != "ESTABLISHED":
                    continue
                if not c.raddr:
                    continue
                conns.append({"raddr": f"{c.raddr.ip}:{c.raddr.port}",
                              "raddr_ip": c.raddr.ip, "raddr_port": c.raddr.port,
                              "pid": c.pid or 0})
        except Exception:
            pass
    return conns


def _get_scheduled_tasks():
    tasks = []
    try:
        ps = ("Get-ScheduledTask | Select-Object TaskName, TaskPath,"
              "@{N='Run';E={$_.Actions.Execute}},"
              "@{N='Author';E={$_.Author}} |"
              "ConvertTo-Csv -NoTypeInformation")
        rc, out, err = _run_hidden(["powershell", "-NoProfile", "-Command", ps],
                                    timeout=60, encoding="utf-8")
        if rc != 0 or not out:
            return tasks
        reader = csv.DictReader(io.StringIO(out))
        for row in reader:
            name = (row.get("TaskName") or "").strip()
            path = (row.get("TaskPath") or "").strip()
            run = (row.get("Run") or "").strip()
            author = (row.get("Author") or "").strip()
            if not name or not run:
                continue
            full_name = f"{path}{name}" if path else name
            tasks.append({"name": full_name, "run": run, "author": author})
    except Exception:
        pass
    return tasks


def _extract_exe_path(value):
    if not value:
        return ""
    value = value.strip()
    if value.startswith('"'):
        end = value.find('"', 1)
        if end > 0:
            return value[1:end]
    if " " in value:
        low = value.lower()
        idx = low.find(".exe")
        if idx >= 0:
            return value[:idx + 4]
    return value.split(" ")[0]


def scan_threats():
    findings = []
    processes = _get_process_list()
    pid_to_proc = {p["pid"]: p for p in processes}

    for p in processes:
        name = (p["name"] or "").lower()
        exe = p.get("exe") or ""
        base = name[:-4] if name.endswith(".exe") else name
        if base in MINER_PROCESSES:
            findings.append({"type": "process", "severity": "critical", "category": "Майнер",
                             "title": f"Обнаружен майнер: {p['name']}",
                             "detail": f"PID: {p['pid']}   ·   {exe or '?'}",
                             "action_data": {"action": "kill", "pid": p["pid"], "name": p["name"]}})
            continue
        if base in RAT_PROCESSES:
            findings.append({"type": "process", "severity": "critical", "category": "RAT",
                             "title": f"Обнаружен RAT: {p['name']}",
                             "detail": f"PID: {p['pid']}   ·   {exe or '?'}",
                             "action_data": {"action": "kill", "pid": p["pid"], "name": p["name"]}})
            continue
        if base in STEALER_PROCESSES:
            findings.append({"type": "process", "severity": "critical", "category": "Стилер",
                             "title": f"Обнаружен стилер: {p['name']}",
                             "detail": f"PID: {p['pid']}   ·   {exe or '?'}",
                             "action_data": {"action": "kill", "pid": p["pid"], "name": p["name"]}})
            continue

    for entry in _get_startup_entries():
        value = entry.get("value", "")
        if not value:
            continue
        exe_path = _extract_exe_path(value)
        if not exe_path:
            continue
        base = os.path.splitext(os.path.basename(exe_path))[0].lower()
        cat = None
        if base in MINER_PROCESSES:
            cat = "Майнер"
        elif base in RAT_PROCESSES:
            cat = "RAT"
        elif base in STEALER_PROCESSES:
            cat = "Стилер"
        if cat:
            findings.append({"type": "startup", "severity": "critical", "category": cat,
                             "title": f"{cat} в автозагрузке: {os.path.basename(exe_path)}",
                             "detail": f"{entry['source']}   ·   {entry['name']} → {exe_path[:120]}",
                             "action_data": {"action": "startup", "source": entry["source"],
                                             "name": entry["name"], "value": value}})

    for c in _get_network_connections():
        port = c.get("raddr_port", 0)
        if port not in SUSPICIOUS_PORTS:
            continue
        proc = pid_to_proc.get(c["pid"])
        if not proc:
            continue
        pn = (proc["name"] or "").lower()
        base = pn[:-4] if pn.endswith(".exe") else pn
        cat = None
        if base in MINER_PROCESSES:
            cat = "Майнер"
        elif base in RAT_PROCESSES:
            cat = "RAT"
        elif base in STEALER_PROCESSES:
            cat = "Стилер"
        else:
            continue
        findings.append({"type": "network", "severity": "critical", "category": cat,
                         "title": f"{cat} активен в сети: {proc['name']}",
                         "detail": f"{c['raddr']}   ·   PID {c['pid']}",
                         "action_data": {"action": "network", "pid": c["pid"],
                                         "raddr": c["raddr"], "proc_name": proc["name"]}})

    for t in _get_scheduled_tasks():
        name = t.get("name", "")
        run = t.get("run", "")
        author = t.get("author", "")
        if not name or not run:
            continue
        run_exe = _extract_exe_path(run)
        if not run_exe:
            continue
        base = os.path.splitext(os.path.basename(run_exe))[0].lower()
        cat = None
        if base in MINER_PROCESSES:
            cat = "Майнер"
        elif base in RAT_PROCESSES:
            cat = "RAT"
        elif base in STEALER_PROCESSES:
            cat = "Стилер"
        if cat:
            findings.append({"type": "scheduled_task", "severity": "critical",
                             "category": cat,
                             "title": f"{cat} в Планировщике задач: {base}",
                             "detail": f"Задача: {name}\nПуть: {run_exe[:140]}",
                             "action_data": {"action": "kill_task", "task_name": name}})
            continue
        run_low = run_exe.lower()
        dangerous = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                     "\\users\\public\\", "\\downloads\\"]
        author_low = author.lower()
        is_ms = "microsoft" in author_low or "\\microsoft\\" in name.lower()
        if any(d in run_low for d in dangerous) and not is_ms:
            findings.append({"type": "scheduled_task", "severity": "high",
                             "category": "Планировщик",
                             "title": "Задача из опасной папки",
                             "detail": f"Задача: {name}\nПуть: {run_exe[:140]}\nАвтор: {author or '?'}",
                             "action_data": {"action": "kill_task", "task_name": name}})

    return findings


def quarantine_list():
    return load_json(QUARANTINE_DB, {"files": []}).get("files", [])


def quarantine_save(files):
    save_json(QUARANTINE_DB, {"files": files})


def quarantine_add(filepath):
    if not os.path.isfile(filepath):
        return False
    files = quarantine_list()
    fid = uuid.uuid4().hex
    ext = os.path.splitext(filepath)[1]
    qpath = os.path.join(QUARANTINE_DIR, fid + ext)
    try:
        shutil.move(filepath, qpath)
    except Exception:
        return False
    files.append({"id": fid, "name": os.path.basename(filepath),
                  "original_path": filepath, "quarantine_path": qpath,
                  "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    quarantine_save(files)
    return True


def quarantine_restore(fid):
    files = quarantine_list()
    for f in list(files):
        if f["id"] == fid:
            try:
                os.makedirs(os.path.dirname(f["original_path"]), exist_ok=True)
                if os.path.exists(f["original_path"]):
                    return False
                shutil.move(f["quarantine_path"], f["original_path"])
                files.remove(f)
                quarantine_save(files)
                return True
            except Exception:
                return False
    return False


def quarantine_delete(fid):
    files = quarantine_list()
    for f in list(files):
        if f["id"] == fid:
            try:
                if os.path.exists(f["quarantine_path"]):
                    os.remove(f["quarantine_path"])
                files.remove(f)
                quarantine_save(files)
                return True
            except Exception:
                return False
    return False


CTX_KEY = r"Software\Classes\*\shell\SentryX"


def install_context_menu():
    if not HAS_WINREG:
        return False
    try:
        exe = sys.executable
        script = os.path.abspath(__file__)
        cmd = (f'"{exe}" --scan "%1"' if getattr(sys, "frozen", False)
               else f'"{exe}" "{script}" --scan "%1"')
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CTX_KEY) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Проверить в SentryX")
            winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, f'"{exe}"')
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CTX_KEY + r"\command") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, cmd)
        return True
    except Exception:
        return False


def uninstall_context_menu():
    if not HAS_WINREG:
        return False
    try:
        def del_key(path):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_ALL_ACCESS) as k:
                    winreg.DeleteKey(k, "command")
            except Exception:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except Exception:
                pass
        del_key(CTX_KEY)
        return True
    except Exception:
        return False


def is_ctx_installed():
    if not HAS_WINREG:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, CTX_KEY, 0, winreg.KEY_READ):
            return True
    except Exception:
        return False


def hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*[max(0, min(255, int(x))) for x in rgb])


def lerp_color(c1, c2, t):
    a, b = hex_to_rgb(c1), hex_to_rgb(c2)
    return rgb_to_hex(tuple(a[i] + (b[i] - a[i]) * t for i in range(3)))


class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, bg, fg, hover_bg, hover_fg,
                 width=180, height=44, radius=10, font=("Segoe UI", 10, "bold"),
                 canvas_bg=None):
        super().__init__(parent, width=width, height=height,
                         bg=canvas_bg or bg, highlightthickness=0, bd=0)
        self.command = command
        self.bg, self.fg = bg, fg
        self.hover_bg, self.hover_fg = hover_bg, hover_fg
        self.radius = radius
        self.w, self.h = width, height
        self.text = text
        self.font = font
        self.enabled = True
        self._draw(self.bg, self.fg)
        self.bind("<Button-1>", self._click)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.configure(cursor="hand2")

    def _rrect(self, x1, y1, x2, y2, r, **kw):
        pts = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r,
               x2, y2-r, x2, y2, x2-r, y2, x1+r, y2,
               x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        return self.create_polygon(pts, smooth=True, **kw)

    def _draw(self, bg, fg):
        self.delete("all")
        self._rrect(2, 2, self.w - 2, self.h - 2, self.radius, fill=bg, outline=bg)
        self.create_text(self.w / 2, self.h / 2, text=self.text, fill=fg, font=self.font)

    def _click(self, e):
        if self.enabled and self.command:
            self.command()

    def _enter(self, e):
        if self.enabled:
            self._draw(self.hover_bg, self.hover_fg)

    def _leave(self, e):
        if self.enabled:
            self._draw(self.bg, self.fg)

    def set_enabled(self, state):
        self.enabled = state
        if state:
            self.configure(cursor="hand2")
            self._draw(self.bg, self.fg)
        else:
            self.configure(cursor="")
            self._draw("#3d4658", "#7a8699")


def draw_ui_icon(canvas, key, color):
    """Draw consistent outline icons in a compact security product style."""
    canvas.delete("all")
    canvas.configure(width=22, height=22)
    line = {"fill": color, "width": 1.7, "capstyle": "round", "joinstyle": "round"}
    if key == "home":
        canvas.create_line(3, 10, 11, 3, 19, 10, **line)
        canvas.create_line(6, 9, 6, 19, 16, 19, 16, 9, **line)
        canvas.create_line(9, 19, 9, 13, 13, 13, 13, 19, **line)
    elif key == "brand":
        canvas.create_line(11, 2, 18, 5, 17, 12, 14, 17, 11, 20, 8, 17, 5, 12, 4, 5, 11, 2, **line)
        canvas.create_line(8, 11, 10, 13, 14, 9, **line)
    elif key == "log":
        canvas.create_line(6, 3, 13, 3, 18, 8, 18, 19, 5, 19, 5, 3, 6, 3, **line)
        canvas.create_line(13, 3, 13, 8, 18, 8, **line)
        for y in (11, 14, 17):
            canvas.create_line(8, y, 15, y, **line)
    elif key == "quarantine":
        canvas.create_line(11, 2, 18, 5, 17, 12, 14, 17, 11, 20, 8, 17, 5, 12, 4, 5, 11, 2, **line)
        canvas.create_arc(7, 6, 15, 14, start=0, extent=180, style="arc",
                          outline=color, width=1.7)
        canvas.create_rectangle(6, 10, 16, 18, outline=color, width=1.7)
        canvas.create_oval(10, 12, 12, 14, fill=color, outline=color)
        canvas.create_line(11, 14, 11, 16, **line)
    elif key == "repair":
        canvas.create_line(3, 8, 5, 6, 8, 8, 8, 11, 11, 14, 14, 11, 17, 8, 20, 11, 17, 14, 14, 17, 11, 20, 8, 17, 5, 14, 3, 11, 3, 8, **line)
        canvas.create_line(13, 12, 18, 7, **line)
        canvas.create_line(16, 5, 19, 4, 18, 7, **line)
    elif key == "settings":
        for y, x in ((6, 8), (11, 14), (16, 10)):
            canvas.create_line(3, y, 19, y, **line)
            canvas.create_oval(x - 2, y - 2, x + 2, y + 2, fill=color, outline=color)
    elif key == "premium":
        canvas.create_line(11, 2, 13.5, 8, 20, 8.5, 15, 13, 16.5, 20, 11, 16.5, 5.5, 20, 7, 13, 2, 8.5, 8.5, 8, 11, 2, **line)
    elif key == "about":
        canvas.create_oval(3, 3, 19, 19, outline=color, width=1.7)
        canvas.create_oval(10, 6, 12, 8, fill=color, outline=color)
        canvas.create_line(11, 10, 11, 16, **line)
    elif key == "speed":
        canvas.create_arc(3, 3, 19, 19, start=25, extent=130, style="arc",
                          outline=color, width=1.7)
        canvas.create_line(5, 15, 7, 13, **line)
        canvas.create_line(17, 15, 15, 13, **line)
        canvas.create_line(11, 13, 15, 8, **line)
        canvas.create_oval(9.5, 11.5, 12.5, 14.5, fill=color, outline=color)
    elif key == "search":
        canvas.create_oval(3, 3, 14, 14, outline=color, width=1.8)
        canvas.create_line(12, 12, 19, 19, **line)
    elif key == "privacy":
        canvas.create_arc(6, 2, 16, 14, start=0, extent=180, style="arc",
                          outline=color, width=1.7)
        canvas.create_rectangle(4, 9, 18, 20, outline=color, width=1.7)
        canvas.create_oval(10, 12, 12, 14, fill=color, outline=color)
        canvas.create_line(11, 14, 11, 17, **line)
    elif key == "license":
        canvas.create_oval(4, 3, 18, 17, outline=color, width=1.7)
        canvas.create_polygon(8, 16, 7, 21, 11, 19, 15, 21, 14, 16, fill=color, outline=color)
        canvas.create_line(11, 6, 12.5, 9, 16, 9.5, 13.5, 12, 14, 15, 11, 13.5, 8, 15, 8.5, 12, 6, 9.5, 9.5, 9, 11, 6, **line)

class NavTab(tk.Frame):
    def __init__(self, parent, icon, text, command, colors, key,
                 on_hover, on_leave, on_click):
        super().__init__(parent, bg=colors["BG_2"], cursor="hand2", height=44)
        self.colors = colors
        self.key = key
        self.command = command
        self._hover_progress = 0.0
        self._hover_target = 0.0
        self._hover_job = None
        self._active = False
        self.pack_propagate(False)
        self.indicator = tk.Frame(self, bg=colors["BG_2"], width=3)
        self.indicator.pack(side="left", fill="y")
        self.inner = tk.Frame(self, bg=colors["BG_2"])
        self.inner.pack(side="left", fill="both", expand=True, padx=(11, 8))
        self.icon_canvas = tk.Canvas(self.inner, width=22, height=22,
                                     bg=colors["BG_2"], highlightthickness=0)
        self.icon_canvas.pack(side="left", padx=(1, 10), pady=10)
        draw_ui_icon(self.icon_canvas, key, colors["FG_DIM"])
        self.text_lbl = tk.Label(self.inner, text=text, bg=colors["BG_2"],
                                 fg=colors["FG_DIM"], font=("Segoe UI", 9))
        self.text_lbl.pack(side="left")
        for w in (self, self.inner, self.icon_canvas, self.text_lbl):
            w.bind("<Button-1>", lambda e: on_click(key))
            w.bind("<Enter>", lambda e: on_hover(key))
            w.bind("<Leave>", lambda e: on_leave(key))

    def set_active(self, active):
        c = self.colors
        self._active = active
        if self._hover_job:
            try:
                self.after_cancel(self._hover_job)
            except Exception:
                pass
            self._hover_job = None
        self._hover_progress = 0.0
        self._hover_target = 0.0
        bg = c["CARD_2"] if active else c["BG_2"]
        for w in (self, self.inner, self.text_lbl):
            w.configure(bg=bg)
        self.text_lbl.configure(fg=c["FG"] if active else c["FG_DIM"],
                                font=("Segoe UI", 9, "bold" if active else "normal"))
        self.icon_canvas.configure(bg=bg)
        self.indicator.configure(bg=c["ACCENT"] if active else c["BG_2"])
        draw_ui_icon(self.icon_canvas, self.key, c["ACCENT"] if active else c["FG_DIM"])

    def set_hover(self, on):
        if self._active:
            return
        self._hover_target = 1.0 if on else 0.0
        if self._hover_job:
            try:
                self.after_cancel(self._hover_job)
            except Exception:
                pass
        self._animate_hover()

    def _animate_hover(self):
        c = self.colors
        delta = self._hover_target - self._hover_progress
        if abs(delta) < 0.06:
            self._hover_progress = self._hover_target
            self._hover_job = None
        else:
            self._hover_progress += delta * 0.38
        t = self._hover_progress
        bg = lerp_color(c["BG_2"], c["CARD_2"], t)
        fg = lerp_color(c["FG_DIM"], c["ACCENT"], t)
        for w in (self, self.inner, self.text_lbl):
            w.configure(bg=bg)
        self.icon_canvas.configure(bg=bg)
        self.text_lbl.configure(fg=fg)
        self.indicator.configure(bg=lerp_color(c["BG_2"], c["ACCENT"], t),
                                 width=3 + round(2 * t))
        draw_ui_icon(self.icon_canvas, self.key, fg)
        if self._hover_progress != self._hover_target:
            self._hover_job = self.after(16, self._animate_hover)


# ==================== REPAIR HELPERS ====================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def repair_backup_dir():
    d = os.path.join(CONFIG_DIR, "Backups")
    os.makedirs(d, exist_ok=True)
    return d


def _is_pure_progress_bar(s):
    return bool(re.match(
        r'^\[\s*[=\-\s>.]*\s*\]\s*\d+(?:\.\d+)?\s*%\s*$', s
    ))


def _extract_progress(line):
    if not line:
        return None
    s = line.strip()
    if not s:
        return None
    m = re.search(r'\[\s*[=\-\s>.]*\]\s*(\d+(?:\.\d+)?)\s*%', s)
    if not m:
        m = re.search(r'(\d+(?:\.\d+)?)\s*%', s)
    if m:
        try:
            val = int(float(m.group(1)))
            if 0 <= val <= 100:
                return val
        except Exception:
            pass
    return None


def _looks_like_garbled_utf16(s):
    if not s or len(s) < 6:
        return False
    stripped = s.strip()
    if "  " not in stripped and stripped.count(" ") < 4:
        return False
    parts = stripped.split(" ")
    if len(parts) < 5:
        return False
    singles = sum(1 for p in parts if len(p) == 1)
    return singles >= len(parts) * 0.6


def _try_reinterpret_as_utf16(s):
    if not _looks_like_garbled_utf16(s):
        return s
    result = []
    for ch in s:
        if ch == " ":
            continue
        result.append(ch)
    return "".join(result)


def _clean_text(s):
    if not s:
        return s
    if "\x00" in s:
        s = s.replace("\x00", "")
    s = _try_reinterpret_as_utf16(s)
    return s


def run_streaming(cmd, on_line, on_done, encoding="cp866", shell=False,
                  on_progress=None):
    def worker():
        try:
            p = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
                shell=shell)

            detected = None
            buf_bytes = bytearray()
            text_buf = ""
            leftover = ""

            def emit_line(line):
                if not line.strip():
                    return
                pct = _extract_progress(line)
                if on_progress and pct is not None:
                    try:
                        on_progress(pct)
                    except Exception:
                        pass
                if _is_pure_progress_bar(line.strip()):
                    return
                line = _clean_text(line)
                if not line.strip():
                    return
                try:
                    on_line(line)
                except Exception:
                    pass

            while True:
                chunk = p.stdout.read(8192)
                if not chunk:
                    break
                buf_bytes.extend(chunk)

                if detected is None and len(buf_bytes) >= 8:
                    if buf_bytes[:2] == b'\xff\xfe':
                        detected = 'utf-16-le'
                        del buf_bytes[:2]
                    elif buf_bytes[:2] == b'\xfe\xff':
                        detected = 'utf-16-be'
                        del buf_bytes[:2]
                    elif buf_bytes[:3] == b'\xef\xbb\xbf':
                        detected = 'utf-8'
                        del buf_bytes[:3]
                    else:
                        sample = bytes(buf_bytes[:min(8192, len(buf_bytes))])
                        pairs = len(sample) // 2
                        if pairs > 4:
                            odd_nulls = sum(1 for i in range(1, len(sample), 2)
                                            if sample[i] == 0)
                            even_nulls = sum(1 for i in range(0, len(sample), 2)
                                             if sample[i] == 0)
                            if odd_nulls > pairs * 0.25:
                                detected = 'utf-16-le'
                            elif even_nulls > pairs * 0.25:
                                detected = 'utf-16-be'
                            else:
                                try:
                                    sample.decode('utf-8')
                                    detected = 'utf-8'
                                except UnicodeDecodeError:
                                    detected = encoding
                        else:
                            try:
                                sample.decode('utf-8')
                                detected = 'utf-8'
                            except UnicodeDecodeError:
                                detected = encoding

                if detected == 'utf-16-le':
                    usable = len(buf_bytes) - (len(buf_bytes) % 2)
                    if usable == 0:
                        continue
                    text_buf += bytes(buf_bytes[:usable]).decode(
                        'utf-16-le', errors='replace')
                    del buf_bytes[:usable]
                elif detected == 'utf-16-be':
                    usable = len(buf_bytes) - (len(buf_bytes) % 2)
                    if usable == 0:
                        continue
                    text_buf += bytes(buf_bytes[:usable]).decode(
                        'utf-16-be', errors='replace')
                    del buf_bytes[:usable]
                elif detected:
                    text_buf += bytes(buf_bytes).decode(
                        detected, errors='replace')
                    buf_bytes.clear()

                while True:
                    m = re.search(r'[\r\n]', text_buf)
                    if not m:
                        break
                    line = leftover + text_buf[:m.start()]
                    text_buf = text_buf[m.end():]
                    leftover = ""
                    emit_line(line)

                if len(text_buf) > 8192:
                    leftover += text_buf[:2000]
                    text_buf = text_buf[2000:]

            if buf_bytes:
                try:
                    if detected == 'utf-16-le':
                        usable = len(buf_bytes) - (len(buf_bytes) % 2)
                        text_buf += bytes(buf_bytes[:usable]).decode(
                            'utf-16-le', errors='replace')
                    elif detected == 'utf-16-be':
                        usable = len(buf_bytes) - (len(buf_bytes) % 2)
                        text_buf += bytes(buf_bytes[:usable]).decode(
                            'utf-16-be', errors='replace')
                    else:
                        text_buf += bytes(buf_bytes).decode(
                            detected or encoding, errors='replace')
                except Exception:
                    pass
            if text_buf.strip():
                emit_line(leftover + text_buf)

            p.wait()
            on_done(p.returncode)
        except Exception as e:
            try:
                on_line(f"[error] {e}")
            except Exception:
                pass
            on_done(-1)

    threading.Thread(target=worker, daemon=True).start()


BACKUP_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def recover_windows_access_settings():
    """Back up and repair common policy and logon-shell restrictions."""
    if not HAS_WINREG:
        return None, 0, 0

    hives = {"HKCU": winreg.HKEY_CURRENT_USER,
             "HKLM": winreg.HKEY_LOCAL_MACHINE}
    win_dir = os.environ.get("WINDIR", r"C:\Windows")
    winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    system_policy = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    explorer_policy = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    # (hive, key, value name, expected value, registry type); None means delete.
    repairs = [
        ("HKLM", winlogon, "Shell", "explorer.exe", winreg.REG_SZ),
        ("HKLM", winlogon, "Userinit",
         os.path.join(win_dir, "system32", "userinit.exe") + ",", winreg.REG_SZ),
    ]
    for hive in ("HKCU", "HKLM"):
        for name in ("DisableTaskMgr", "DisableRegistryTools", "DisableCMD",
                     "DisableChangePassword", "DisableLockWorkstation"):
            repairs.append((hive, system_policy, name, None, None))
        repairs.append((hive, explorer_policy, "NoClose", None, None))
        for exe_name in ("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe",
                         "narrator.exe", "taskmgr.exe"):
            repairs.append((
                hive,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + exe_name,
                "Debugger", None, None))

    backup = {"created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              "values": []}
    for hive_name, path, name, expected, value_type in repairs:
        previous = None
        try:
            with winreg.OpenKey(hives[hive_name], path, 0, winreg.KEY_READ) as key:
                previous = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        backup["values"].append({
            "hive": hive_name, "path": path, "name": name,
            "existed": previous is not None,
            "type": previous[1] if previous else None,
            "value": previous[0] if previous else None,
        })

    backup_path = os.path.join(
        repair_backup_dir(),
        "access_recovery_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".json")
    try:
        with open(backup_path, "w", encoding="utf-8") as f:
            json.dump(backup, f, ensure_ascii=False, indent=2)
    except Exception:
        return None, 0, len(repairs)

    changed = errors = 0
    for hive_name, path, name, expected, value_type in repairs:
        try:
            if expected is None:
                try:
                    key = winreg.OpenKey(hives[hive_name], path, 0, winreg.KEY_SET_VALUE)
                except FileNotFoundError:
                    continue
            else:
                key = winreg.CreateKeyEx(
                    hives[hive_name], path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
            with key:
                try:
                    old_value, old_type = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    old_value, old_type = None, None
                if expected is None:
                    if old_value is not None:
                        winreg.DeleteValue(key, name)
                        changed += 1
                elif old_value != expected or old_type != value_type:
                    winreg.SetValueEx(key, name, 0, value_type, expected)
                    changed += 1
        except Exception:
            errors += 1
    return backup_path, changed, errors


def _read_reg_key(hive_name, path):
    if not HAS_WINREG:
        return {}
    hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
    out = {}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                    out[name] = value
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return out


def backup_autorun():
    try:
        data = {"created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "keys": {}}
        for hive, path in BACKUP_RUN_KEYS:
            values = _read_reg_key(hive, path)
            if values:
                data["keys"][f"{hive}\\{path}"] = values
        fp = os.path.join(repair_backup_dir(), "autorun_backup.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return fp
    except Exception:
        return None


def restore_autorun():
    if not HAS_WINREG:
        return (0, "winreg not available")
    fp = os.path.join(repair_backup_dir(), "autorun_backup.json")
    if not os.path.isfile(fp):
        return (0, "backup not found")
    try:
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return (0, str(e))
    restored = 0
    errors = 0
    for full_path, values in data.get("keys", {}).items():
        if "\\" not in full_path:
            continue
        hive_name, path = full_path.split("\\", 1)
        hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_WRITE) as k:
                for name, value in values.items():
                    try:
                        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
                        restored += 1
                    except Exception:
                        errors += 1
        except Exception:
            errors += 1
    return (restored, errors)


def list_restore_points():
    try:
        ps = ("Get-ComputerRestorePoint | "
              "Select-Object SequenceNumber, Description, "
              "@{N='Date';E={$_.ConvertToDateTime($_.CreationTime)}} | "
              "ConvertTo-Csv -NoTypeInformation")
        rc, out, err = _run_hidden(["powershell", "-NoProfile", "-Command", ps],
                                    timeout=30, encoding="utf-8")
        if rc != 0 or not out:
            return []
        reader = csv.DictReader(io.StringIO(out))
        pts = []
        for row in reader:
            pts.append({"seq": (row.get("SequenceNumber") or "").strip(),
                        "desc": (row.get("Description") or "").strip(),
                        "date": (row.get("Date") or "").strip()})
        return pts
    except Exception:
        return []


def create_restore_point(desc="SentryX"):
    try:
        ps = ("Checkpoint-Computer -Description '{d}' "
              "-RestorePointType 'MODIFY_SETTINGS'").format(d=desc)
        rc, out, err = _run_hidden(
            ["powershell", "-NoProfile", "-Command", ps],
            timeout=300, encoding="utf-8")
        return (rc == 0, (out or "") + (err or ""))
    except Exception as e:
        return (False, str(e))


# ==================== ПРИЛОЖЕНИЕ ====================
class SentryXApp:
    def __init__(self, root, startup_scan=None):
        self.root = root
        self.startup_scan = startup_scan
        cfg = load_json(CONFIG_FILE, {}) if CONFIG_FILE else {}
        self.lang = cfg.get("lang", "ru")
        self.theme = cfg.get("theme", "dark")
        self.visual_scene = cfg.get("visual_scene", "aurora")
        if self.visual_scene not in VISUAL_SCENES:
            self.visual_scene = "aurora"
        self.wallpaper_path = cfg.get("wallpaper_path", "")
        try:
            self.wallpaper_focus_x = min(1.0, max(0.0, float(cfg.get("wallpaper_focus_x", 0.5))))
            self.wallpaper_focus_y = min(1.0, max(0.0, float(cfg.get("wallpaper_focus_y", 0.5))))
        except (TypeError, ValueError):
            self.wallpaper_focus_x = self.wallpaper_focus_y = 0.5
        self._wallpaper_drag_point = None
        self.scene_effect = cfg.get("scene_effect", "off")
        if self.scene_effect not in {"off", "snow", "rain"}:
            self.scene_effect = "off"
        self.tier = cfg.get("tier", "free")
        if self.tier not in {"free", "tester"}:
            self.tier = "free"
        self.auto_downloads = cfg.get("auto_downloads", False)
        self.notifications_enabled = cfg.get("notifications", True)
        self.realtime_protection = cfg.get("realtime_protection", True)
        self.current_user = get_current_user()
        self.page = "home"
        self.log_lines = []
        self.folder_path = cfg.get("folder", os.path.expanduser("~/Downloads"))
        self.is_scanning = False
        self.stop_flag = False
        self.threats_found = 0
        self.live_counter_stop = False
        self.pulse_phase = 0
        self._pulse_job = None
        self._splash_job = None
        self._ctx_render = None
        self._pending_scan_job = None
        self._observer = None
        self._last_threat_findings = None
        self._downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
        self._drag_data = {"x": 0, "y": 0}
        self._is_maximized = False
        self._saved_geo = None
        self.tray = None
        self.tray_notified = False
        self.log_filter = "all"
        self.log_search = ""
        self._log_filter_buttons = {}
        self._update_dialog = None
        self._progress_dialogs = {"sfc": None, "dism": None}
        self._protection_monitor = None
        self._scene_canvas = None
        self._scene_after = None
        self._scene_resize_job = None
        self._scene_photo = None
        self._scene_particles = []
        self._scene_last_frame = None

        self.root.title(f"{APP_NAME} · {APP_VERSION}")
        self.root.configure(bg=self.C["BG"])
        self.root.overrideredirect(True)
        self.root.minsize(1180, 700)
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass
        self._center_window(1180, 820)
        self._build_splash()
        self._setup_tray()
        self._start_pending_scan_watcher()
        self.root.after(2000, self._maybe_start_watcher)

    @property
    def C(self):
        palette = THEMES[self.theme].copy()
        palette.update({k: v for k, v in VISUAL_SCENES[self.visual_scene].items()
                        if k in {"ACCENT", "ACCENT_2", "GREEN"}})
        return palette

    @property
    def T(self):
        return TEXTS[self.lang]

    def _notify(self, title, message):
        if not self.notifications_enabled:
            return
        if self.tray:
            try:
                self.tray.notify(message, title)
                return
            except Exception:
                pass
        try:
            self._log(f"🔔 {title}: {message}", "info")
        except Exception:
            pass

    def _show_in_taskbar(self):
        try:
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            style = style & ~WS_EX_TOOLWINDOW
            style = style | WS_EX_APPWINDOW
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
            self.root.withdraw()
            self.root.after(10, self._deiconify_taskbar)
        except Exception:
            pass

    def _deiconify_taskbar(self):
        try:
            self.root.deiconify()
            self.root.overrideredirect(True)
        except Exception:
            pass

    def _maybe_start_watcher(self):
        if self.auto_downloads and HAS_WATCHDOG:
            self._start_downloads_watcher()

    def _start_downloads_watcher(self):
        if not HAS_WATCHDOG:
            return False
        if self._observer is not None:
            return True
        if not os.path.isdir(self._downloads_path):
            return False
        try:
            handler = DownloadsHandler(self)
            self._observer = Observer()
            self._observer.schedule(handler, self._downloads_path, recursive=False)
            self._observer.daemon = True
            self._observer.start()
            self._log(f"👁  Автопроверка Загрузок активна: {self._downloads_path}", "info")
            return True
        except Exception as e:
            self._log(f"⚠  Не удалось запустить автопроверку: {e}", "warn")
            self._observer = None
            return False

    def _stop_downloads_watcher(self):
        if self._observer is None:
            return
        try:
            self._observer.stop()
            self._observer.join(timeout=2)
        except Exception:
            pass
        self._observer = None
        self._log("👁  Автопроверка Загрузок остановлена", "dim")

    def _start_protection_monitor(self):
        if self._protection_monitor is None:
            self._protection_monitor = ProtectionMonitor(self)
        if self.realtime_protection:
            self._protection_monitor.start()
            self._log(self.T["prot_enabled_log"], "ok")
            self._log(self.T["prot_started"], "ok")

    def _stop_protection_monitor(self):
        if self._protection_monitor is not None:
            self._protection_monitor.stop()
            if self.realtime_protection:
                self._log(self.T["prot_stopped"], "dim")

    def _toggle_realtime_protection(self):
        self.realtime_protection = not self.realtime_protection
        self._save_config()
        if self.realtime_protection:
            self._start_protection_monitor()
        else:
            self._stop_protection_monitor()
        self._rebuild_preserve()

    def _toggle_auto_downloads(self):
        if not HAS_WATCHDOG:
            messagebox.showwarning(self.T["err_title"], self.T["watchdog_missing"])
            return
        self.auto_downloads = not self.auto_downloads
        self._save_config()
        if self.auto_downloads:
            if not self._start_downloads_watcher():
                self.auto_downloads = False
                self._save_config()
                messagebox.showerror(self.T["err_title"],
                                     "Не удалось запустить автопроверку" if self.lang == "ru"
                                     else "Failed to start auto-scan")
        else:
            self._stop_downloads_watcher()
        self._rebuild_preserve()

    def _toggle_notifications(self):
        self.notifications_enabled = not self.notifications_enabled
        self._save_config()
        self._rebuild_preserve()

    def _toggle_autostart(self):
        if not HAS_WINREG:
            messagebox.showwarning(self.T["err_title"], self.T["set_autostart_unavailable"])
            return
        currently = is_autostart_installed()
        if currently:
            ok = uninstall_autostart()
            msg = self.T["autostart_off"]
        else:
            ok = install_autostart()
            msg = self.T["autostart_ok"]
        if ok:
            self._log(f"🚀 {msg}", "ok")
        else:
            messagebox.showerror(self.T["err_title"], self.T["autostart_err"])
        self._rebuild_preserve()

    def _auto_scan_file(self, path):
        if self.is_scanning:
            return
        name = os.path.basename(path)
        self._log(f"👁  Автопроверка: {name}", "info")

        def worker():
            rc, out, err = run_defender_scan(3, path)
            threats = self._parse_defender_output(out)
            self._add_history(self.T["label_auto"], 1, threats, 0,
                              "danger" if threats > 0 else "clean")
            if threats > 0:
                self.root.after(0, lambda: self._on_auto_threat(path, threats))
            else:
                self.root.after(0, lambda: self._log(f"   ✅ Чисто: {name}", "ok"))
        threading.Thread(target=worker, daemon=True).start()

    def _on_auto_threat(self, path, threats):
        name = os.path.basename(path)
        self._log(f"   🚨 УГРОЗА в загрузке: {name}", "mal")
        self._notify(self.T["notify_title"],
                     self.T["notify_auto_threat"].format(name=name))
        self._offer_quarantine(path)

    def _start_pending_scan_watcher(self):
        def check():
            path = read_pending_scan()
            if path and os.path.exists(path):
                self._bring_to_front()
                self.root.after(200, lambda: self._scan_specific_file(path))
            self._pending_scan_job = self.root.after(700, check)
        self._pending_scan_job = self.root.after(700, check)

    def _bring_to_front(self):
        try:
            self.root.deiconify()
            self.root.overrideredirect(True)
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass

    def _save_config(self):
        save_json(CONFIG_FILE, {
            "lang": self.lang, "theme": self.theme, "tier": self.tier,
            "visual_scene": self.visual_scene,
            "wallpaper_path": self.wallpaper_path,
            "wallpaper_focus_x": self.wallpaper_focus_x,
            "wallpaper_focus_y": self.wallpaper_focus_y,
            "scene_effect": self.scene_effect,
            "folder": self.folder_path,
            "auto_downloads": self.auto_downloads,
            "notifications": self.notifications_enabled,
            "realtime_protection": self.realtime_protection,
        })

    def _add_history(self, scan_type, files_count, threats, duration, result):
        history = load_json(HISTORY_FILE, {"scans": []})
        entry = {"date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "type": scan_type, "files": files_count, "threats": threats,
                 "duration": int(duration), "result": result}
        history.setdefault("scans", []).append(entry)
        history["scans"] = history["scans"][-100:]
        save_json(HISTORY_FILE, history)

    def _get_last_scan(self):
        history = load_json(HISTORY_FILE, {"scans": []})
        scans = history.get("scans", [])
        return scans[-1] if scans else None

    def _center_window(self, w, h):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2 - 30
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _destroy_all(self):
        if self._pulse_job:
            try:
                self.root.after_cancel(self._pulse_job)
            except Exception:
                pass
            self._pulse_job = None
        for job_name in ("_scene_after", "_scene_resize_job"):
            job = getattr(self, job_name, None)
            if job:
                try:
                    self.root.after_cancel(job)
                except Exception:
                    pass
                setattr(self, job_name, None)
        self._scene_canvas = None
        self._scene_photo = None
        self._scene_particles = []
        self._scene_last_frame = None
        for w in self.root.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        c = self.C
        style.configure("Product.Horizontal.TProgressbar",
                        troughcolor=c["CARD_2"], background=c["ACCENT"],
                        bordercolor=c["CARD_2"], lightcolor=c["ACCENT"],
                        darkcolor=c["ACCENT"], thickness=6)
        style.configure("Dark.Vertical.TScrollbar",
                        background=c["CARD_2"], troughcolor=c["CARD"],
                        bordercolor=c["CARD"], arrowcolor=c["FG_DIM"],
                        lightcolor=c["CARD_2"], darkcolor=c["CARD_2"], relief="flat")
        style.map("Dark.Vertical.TScrollbar",
                  background=[("active", c["BORDER"])])

    # ==================== SPLASH ====================
    def _build_splash(self):
        self._destroy_all()
        import math
        import random
        import traceback
        import tkinter.font as tkfont

        try:
            from PIL import Image as PImg, ImageTk as PTk
            has_pil = True
        except Exception:
            has_pil = False

        c = self.C
        dark = (self.theme == "dark")
        ru = (self.lang == "ru")

        # Keep the animated intro's original cinematic palette while the app
        # workspace uses the new, quieter product theme.
        if dark:
            BG1, BG2 = "#150b2e", "#0a0e1a"
            ACC, ACC2, GRN = "#00d9ff", "#a855f7", "#10b981"
            FG, DIM, CARD, BORDER = "#e6edf3", "#7a8699", "#111827", "#1f2a44"
        else:
            BG1, BG2 = "#c7d5ec", "#eef1f7"
            ACC, ACC2, GRN = "#0891b2", "#7c3aed", "#059669"
            FG, DIM, CARD, BORDER = "#0f172a", "#64748b", "#ffffff", "#d4dae6"
        HOT = lerp_color(ACC, "#ffffff", 0.72) if dark else lerp_color(ACC, "#ffffff", 0.35)
        SCAN = HOT if dark else ACC2
        BASE = lerp_color(lerp_color(BG1, BG2, 0.40), ACC, 0.05 if has_pil else 0.0)

        title = APP_NAME
        statuses = ([
            "Инициализация ядра",
            "Загрузка модулей безопасности",
            "Подключение к Windows Defender",
            "Анализ системных ресурсов",
            "Проверка целостности данных",
            "Запуск интерфейса",
        ] if ru else [
            "Initializing core",
            "Loading security modules",
            "Connecting to Windows Defender",
            "Analyzing system resources",
            "Verifying data integrity",
            "Launching interface",
        ])
        final_status = "Защита активна" if ru else "Protection active"

        T_BAR0, T_BAR1 = 0.9, 4.9
        T_DONE = 5.0
        T_WIPE = 5.65
        T_END = 6.25
        T_TITLE = 1.75

        def clamp(v, a=0.0, b=1.0):
            return a if v < a else (b if v > b else v)

        def smooth(u):
            u = clamp(u)
            return u * u * (3 - 2 * u)

        def eout(u):
            u = clamp(u)
            return 1 - (1 - u) ** 3

        def ein(u):
            u = clamp(u)
            return u * u * u

        def mix(a, b, t):
            return lerp_color(a, b, clamp(t))

        try:
            fams = set(tkfont.families(self.root))
        except Exception:
            fams = set()
        mono = next((f for f in ("Cascadia Code", "Cascadia Mono", "Consolas",
                                 "Courier New") if f in fams), "Courier")
        sans = next((f for f in ("Segoe UI Variable Display", "Segoe UI", "Inter",
                                 "Helvetica") if f in fams), "Helvetica")
        title_font = tkfont.Font(root=self.root, family=sans, size=52, weight="bold")

        wrap = tk.Frame(self.root, bg=BASE)
        wrap.pack(fill="both", expand=True)
        canvas = tk.Canvas(wrap, bg=BASE, highlightthickness=0, bd=0)
        canvas.pack(fill="both", expand=True)

        st = {
            "w": 1180, "h": 820, "done": False, "t0": time.perf_counter(),
            "last": time.perf_counter(), "mx": 0.0, "my": 0.0,
            "mx_t": 0.0, "my_t": 0.0, "img_bg": None, "bg_item": None,
            "glow_frames": [], "glow_item": None, "glow_idx": -1,
            "status_idx": -1, "status_t0": 0.0, "next_wave": 1.7,
            "flash_done": False, "wipe_item": None, "bg_after": None,
            "font": title_font,
        }
        G = {}
        cache = {}

        def sf(it, col):
            if cache.get((it, 0)) != col:
                cache[(it, 0)] = col
                canvas.itemconfigure(it, fill=col)

        def so(it, col):
            if cache.get((it, 1)) != col:
                cache[(it, 1)] = col
                canvas.itemconfigure(it, outline=col)

        def vis(tag, on):
            if cache.get(("v", tag)) != on:
                cache[("v", tag)] = on
                canvas.itemconfigure(tag, state="normal" if on else "hidden")

        def oval(it, x, y, r):
            canvas.coords(it, x - r, y - r, x + r, y + r)

        def bez(p0, p1, p2, p3, n):
            pts = []
            for i in range(n + 1):
                t = i / n
                u = 1 - t
                pts.append((
                    u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]))
            return pts

        right = bez((0, -1.2), (0.34, -1.02), (0.66, -0.9), (0.92, -0.9), 14)
        right += [(0.92, -0.9 + 0.75 * i / 6) for i in range(1, 6)]
        right += bez((0.92, -0.15), (0.92, 0.58), (0.46, 0.96), (0, 1.22), 22)
        left = [(-x, y) for x, y in right]
        n_r = len(right)
        SH = right + [(-x, y) for x, y in reversed(right[1:-1])]
        LOGO = 0.60
        hw_ys = [p[1] for p in right]
        hw_xs = [p[0] for p in right]

        def half_width(yu):
            if yu <= hw_ys[0]:
                return 0.0
            if yu >= hw_ys[-1]:
                return 0.0
            lo, hi = 0, len(hw_ys) - 1
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if hw_ys[mid] <= yu:
                    lo = mid
                else:
                    hi = mid
            span = hw_ys[hi] - hw_ys[lo]
            f = 0 if span == 0 else (yu - hw_ys[lo]) / span
            return hw_xs[lo] + (hw_xs[hi] - hw_xs[lo]) * f

        def flat(pts, S, ox, oy):
            out = []
            for x, y in pts:
                out.append(ox + x * S)
                out.append(oy + y * S)
            return out

        def make_bg(w, h):
            if not has_pil:
                canvas.delete("bg")
                steps = 90
                for i in range(steps):
                    col = lerp_color(BG1, BG2, i / (steps - 1))
                    y1 = int(h * i / steps)
                    y2 = int(h * (i + 1) / steps) + 1
                    canvas.create_rectangle(0, y1, w, y2, fill=col, outline=col, tags="bg")
                canvas.tag_lower("bg")
                return
            lin = PImg.linear_gradient("L").resize((w, h))
            base = PImg.composite(PImg.new("RGB", (w, h), BG2), PImg.new("RGB", (w, h), BG1), lin)
            rg = PImg.radial_gradient("L")
            inv = rg.point(lambda v: max(0, int(255 * (1 - v / 179.0))))
            gs = int(max(w, h) * 1.15)
            gm = inv.resize((gs, gs), PImg.BICUBIC).point(
                lambda v: int(255 * ((v / 255.0) ** 1.6) * (0.20 if dark else 0.16)))
            mask = PImg.new("L", (w, h), 0)
            mask.paste(gm, (int(G["cx"] - gs / 2), int(G["cy"] - gs / 2)))
            base = PImg.composite(PImg.new("RGB", (w, h), ACC), base, mask)
            vm = rg.resize((w * 2, h * 2), PImg.BICUBIC).crop((w // 2, h // 2, w // 2 + w, h // 2 + h))
            vm = vm.point(lambda v: int(((v / 255.0) ** 2.2) * 255 * (0.55 if dark else 0.16)))
            vcol = "#000000" if dark else lerp_color(BG1, "#000000", 0.25)
            base = PImg.composite(PImg.new("RGB", (w, h), vcol), base, vm)
            st["img_bg"] = PTk.PhotoImage(base)
            if st["bg_item"] is None:
                st["bg_item"] = canvas.create_image(0, 0, image=st["img_bg"], anchor="nw", tags="bg")
            else:
                canvas.itemconfigure(st["bg_item"], image=st["img_bg"])
            canvas.tag_lower("bg")

        N_GLOW = 20

        def build_glow(R):
            st["glow_frames"] = []
            if not has_pil:
                return
            rgb = hex_to_rgb(ACC)
            inv = PImg.radial_gradient("L").point(lambda v: max(0, int(255 * (1 - v / 179.0))))
            size = int(R * 2)
            bm = inv.resize((size, size), PImg.BICUBIC)
            gmax = 0.55 if dark else 0.42
            for i in range(N_GLOW):
                s = gmax * i / (N_GLOW - 1)
                m = bm.point(lambda v, s=s: int(255 * ((v / 255.0) ** 2.1) * s))
                sp = PImg.new("RGBA", (size, size), rgb + (0,))
                sp.putalpha(m)
                st["glow_frames"].append(PTk.PhotoImage(sp))

        star_cols = [ACC, ACC2, ACC, DIM, GRN]
        stars = []
        for _ in range(110):
            a = random.uniform(0, math.tau)
            stars.append({
                "a": a, "ca": math.cos(a), "sa": math.sin(a),
                "r": random.uniform(6, 900), "sp": random.uniform(0.35, 1.6),
                "col": random.choice(star_cols), "br": random.uniform(0.55, 1.0),
                "it": canvas.create_line(0, 0, 0, 0, fill=BASE, width=1,
                                         capstyle="round", tags="g_star", state="hidden"),
            })

        hexcols = []
        for i in range(10):
            hexcols.append({
                "it": canvas.create_text(0, 0, text="", font=(mono, 9), fill=BASE,
                                         anchor="n", justify="center", tags="g_hex",
                                         state="hidden"),
                "off": random.uniform(0, 600), "sp": random.uniform(14, 34),
                "lines": ["%02X %02X" % (random.randint(0, 255), random.randint(0, 255))
                          for _ in range(20)],
                "next": random.uniform(0, 0.3),
            })

        glow_item = canvas.create_image(0, 0, anchor="center", tags="g_glow", state="hidden")
        st["glow_item"] = glow_item
        glow_ovals = []
        if not has_pil:
            for _ in range(5):
                glow_ovals.append(canvas.create_oval(0, 0, 0, 0, outline="", fill=BASE,
                                                     tags="g_glow", state="hidden"))

        disc = canvas.create_oval(0, 0, 0, 0, fill=BASE, outline=BASE, width=1,
                                  tags="g_disc", state="hidden")
        ring_d = canvas.create_oval(0, 0, 0, 0, fill="", outline=BASE, width=1,
                                    tags="g_ringd", state="hidden")
        ring_c0 = canvas.create_oval(0, 0, 0, 0, fill="", outline=BASE, width=1,
                                     tags="g_ringc", state="hidden")
        fan = [canvas.create_arc(0, 0, 0, 0, start=0, extent=5, style="pieslice",
                                 outline="", fill=BASE, tags="g_fan", state="hidden")
               for _ in range(16)]
        ticks = [canvas.create_line(0, 0, 0, 0, fill=BASE, width=1, tags="g_tick",
                                    state="hidden") for _ in range(72)]
        ringA = [canvas.create_arc(0, 0, 0, 0, start=0, extent=100, style="arc",
                                   outline=BASE, width=3, tags="g_ringa", state="hidden")
                 for _ in range(2)]
        ringC = [canvas.create_arc(0, 0, 0, 0, start=0, extent=48, style="arc",
                                   outline=BASE, width=2, tags="g_ringc", state="hidden")
                 for _ in range(3)]
        comets = []
        comet_cols = [ACC, ACC2, GRN]
        for j in range(3):
            comets.append({
                "a0": random.uniform(0, 360), "sp": [-46, 31, -64][j],
                "col": comet_cols[j],
                "dots": [canvas.create_oval(0, 0, 0, 0, fill=BASE, outline="",
                                            tags="g_comet", state="hidden")
                         for _ in range(9)],
            })

        sh_fill = canvas.create_polygon(0, 0, 0, 0, 0, 0, fill=BASE, outline="",
                                        tags="g_shfill", state="hidden")
        logo_l = canvas.create_polygon(0, 0, 0, 0, 0, 0, fill=BASE, outline="",
                                       tags="g_logo", state="hidden")
        logo_r = canvas.create_polygon(0, 0, 0, 0, 0, 0, fill=BASE, outline=BASE,
                                       width=2, tags="g_logo", state="hidden")
        logo_check = canvas.create_line(0, 0, 0, 0, 0, 0, fill=BASE, width=3.5,
                                        capstyle="round", joinstyle="round",
                                        tags="g_logo", state="hidden")
        sh_lines = []
        for wd in (14, 7, 3):
            pair = [canvas.create_line(0, 0, 0, 0, fill=BASE, width=wd, capstyle="round",
                                       joinstyle="round", tags="g_shline", state="hidden")
                    for _ in range(2)]
            sh_lines.append((wd, pair))
        scan_lines = [canvas.create_line(0, 0, 0, 0, fill=BASE, width=wd, capstyle="round",
                                         tags="g_scan", state="hidden") for wd in (1, 1, 2)]

        letters = []
        for _ in title:
            letters.append({
                "it": canvas.create_text(0, 0, text="", font=title_font, fill=BASE,
                                         anchor="center", tags="g_title", state="hidden"),
                "next": 0.0, "ch": "", "x": 0, "y": 0,
            })
        meta_l = canvas.create_line(0, 0, 0, 0, fill=BASE, width=1, tags="g_meta", state="hidden")
        meta_r = canvas.create_line(0, 0, 0, 0, fill=BASE, width=1, tags="g_meta", state="hidden")
        meta_d = [canvas.create_oval(0, 0, 0, 0, fill=BASE, outline="", tags="g_meta",
                                     state="hidden") for _ in range(3)]
        ver_item = canvas.create_text(0, 0, text=f"v{APP_VERSION}", font=(mono, 12),
                                      fill=BASE, tags="g_meta", state="hidden")
        auth_item = canvas.create_text(0, 0, text=APP_AUTHOR, font=(sans, 10), fill=BASE,
                                       tags="g_meta", state="hidden")

        corners = [canvas.create_line(0, 0, 0, 0, 0, 0, fill=BASE, width=2,
                                      tags="g_corner", state="hidden") for _ in range(4)]
        lab_l = canvas.create_text(0, 0, text="SENTRYX  //  SECURITY SUITE", font=(mono, 9),
                                   fill=BASE, anchor="w", tags="g_corner", state="hidden")
        lab_r = canvas.create_text(0, 0, text=f"BUILD {APP_VERSION.upper()}", font=(mono, 9),
                                   fill=BASE, anchor="e", tags="g_corner", state="hidden")

        N_SEG = 52
        segs = [canvas.create_rectangle(0, 0, 0, 0, fill=BASE, outline="", tags="g_bar",
                                        state="hidden") for _ in range(N_SEG)]
        caret = canvas.create_text(0, 0, text="›", font=(mono, 13, "bold"), fill=BASE,
                                   anchor="w", tags="g_bar", state="hidden")
        status_item = canvas.create_text(0, 0, text="", font=(mono, 11), fill=BASE,
                                         anchor="w", tags="g_bar", state="hidden")
        pct_item = canvas.create_text(0, 0, text="0%", font=(mono, 12, "bold"), fill=BASE,
                                      anchor="e", tags="g_bar", state="hidden")

        waves = []

        def relayout():
            w, h = st["w"], st["h"]
            k = max(0.62, min(1.25, min(w / 1180.0, h / 820.0)))
            G.update(w=w, h=h, k=k, cx=w / 2.0, cy=h * 0.385)
            G.update(S=74 * k, Rd=108 * k, Ra=124 * k, Rt=142 * k, Rc=164 * k, Rr=188 * k)
            cx, cy = G["cx"], G["cy"]

            make_bg(w, h)
            build_glow(262 * k)
            if st["glow_frames"]:
                canvas.coords(glow_item, cx, cy)
                canvas.itemconfigure(glow_item, image=st["glow_frames"][0])
                st["glow_idx"] = -1
            canvas.tag_lower("bg")

            tw = title_font.measure(title)
            x0 = cx - tw / 2.0
            G["title_y"] = cy + 252 * k
            for i, L in enumerate(letters):
                pre = title_font.measure(title[:i])
                lw = title_font.measure(title[i])
                L["x"] = x0 + pre + lw / 2.0
                L["y"] = G["title_y"]
            ly = G["title_y"] + 50 * k
            G["meta_y"] = ly
            canvas.coords(ver_item, cx, ly + 30 * k)
            canvas.coords(auth_item, cx, ly + 54 * k)

            BW = 540 * k
            G["bx0"] = cx - BW / 2.0
            G["BW"] = BW
            G["by"] = h - 62 * k
            gap = 3
            sw = (BW - gap * (N_SEG - 1)) / N_SEG
            for i, it in enumerate(segs):
                xa = G["bx0"] + i * (sw + gap)
                canvas.coords(it, xa, G["by"], xa + sw, G["by"] + 6)
            canvas.coords(caret, G["bx0"], G["by"] - 22)
            canvas.coords(status_item, G["bx0"] + 16, G["by"] - 21)
            canvas.coords(pct_item, G["bx0"] + BW, G["by"] - 21)

            m, arm = 30, 36
            canvas.coords(corners[0], m, m + arm, m, m, m + arm, m)
            canvas.coords(corners[1], w - m - arm, m, w - m, m, w - m, m + arm)
            canvas.coords(corners[2], m, h - m - arm, m, h - m, m + arm, h - m)
            canvas.coords(corners[3], w - m - arm, h - m, w - m, h - m, w - m, h - m - arm)
            canvas.coords(lab_l, m + 14, m + 22)
            canvas.coords(lab_r, w - m - 14, m + 22)

            span = max(40, w * 0.26 - 44)
            for i, hc in enumerate(hexcols):
                if i < 5:
                    hc["x"] = 44 + span * i / 4.0
                else:
                    hc["x"] = w - 44 - span * (i - 5) / 4.0

            for i, it in enumerate(ticks):
                ang = math.radians(i * 5)
                ln = 11 if i % 3 == 0 else 6
                r_in = G["Rt"] - ln / 2.0
                r_out = G["Rt"] + ln / 2.0
                canvas.coords(it, cx + r_in * math.cos(ang), cy - r_in * math.sin(ang),
                              cx + r_out * math.cos(ang), cy - r_out * math.sin(ang))
            oval(ring_d, cx, cy, G["Rr"])
            oval(ring_c0, cx, cy, G["Rc"])
            oval(disc, cx, cy, G["Rd"])
            for it in ringA:
                oval(it, cx, cy, G["Ra"])
            for it in ringC:
                oval(it, cx, cy, G["Rc"])
            for it in fan:
                oval(it, cx, cy, G["Rd"] - 5)
            if not has_pil:
                for i, it in enumerate(glow_ovals):
                    oval(it, cx, cy, (240 - i * 36) * k)

        def on_resize(e):
            if e.width < 300 or e.height < 300:
                return
            if (e.width, e.height) == (st["w"], st["h"]) and st["img_bg"] is not None:
                return
            st["w"], st["h"] = e.width, e.height
            if st["bg_after"]:
                try:
                    self.root.after_cancel(st["bg_after"])
                except Exception:
                    pass
            st["bg_after"] = self.root.after(30, relayout)

        def on_motion(e):
            st["mx_t"] = (e.x / max(1.0, st["w"]) - 0.5) * 2
            st["my_t"] = (e.y / max(1.0, st["h"]) - 0.5) * 2

        canvas.bind("<Configure>", on_resize)
        canvas.bind("<Motion>", on_motion)

        def prog_at(t):
            u = clamp((t - T_BAR0) / (T_BAR1 - T_BAR0))
            kk = 6
            s = u * kk
            fl = int(s)
            stair = 1.0 if fl >= kk else (fl + smooth(s - fl)) / kk
            return 100.0 * (0.35 * u + 0.65 * stair)

        GLYPHS = "ABCDEF0123456789#%&@$<>/\\|=+*"

        def frame():
            now = time.perf_counter()
            t = now - st["t0"]
            dt = clamp(now - st["last"], 0.0, 0.05)
            st["last"] = now
            w, h, k = G["w"], G["h"], G["k"]
            cx, cy = G["cx"], G["cy"]
            S, Rd, Ra, Rt, Rc, Rr = G["S"], G["Rd"], G["Ra"], G["Rt"], G["Rc"], G["Rr"]

            st["mx"] += (st["mx_t"] - st["mx"]) * 0.06
            st["my"] += (st["my_t"] - st["my"]) * 0.06

            dm = smooth((t - T_DONE) / 0.5)
            P = mix(ACC, GRN, dm)
            pulse = (math.sin(t * 2.3) + 1) / 2

            v = 36 + 1500 * math.exp(-t * 1.9)
            fs = smooth(t / 0.4)
            vis("g_star", fs > 0.01)
            ox = cx + st["mx"] * 18 * k
            oy = cy + st["my"] * 12 * k
            maxr = math.hypot(w, h) / 2 + 30
            dust = 0.50 + 0.50 * min(1.0, v / 420.0)
            for s in stars:
                s["r"] += v * s["sp"] * dt * (0.25 + s["r"] / 300.0)
                if s["r"] > maxr:
                    s["r"] = random.uniform(8, 70)
                    s["a"] = random.uniform(0, math.tau)
                    s["ca"], s["sa"] = math.cos(s["a"]), math.sin(s["a"])
                r = s["r"]
                ln = max(1.5, v * 0.05 * s["sp"] * (0.3 + r / 300.0))
                r0 = max(0.0, r - ln)
                canvas.coords(s["it"], ox + r0 * s["ca"], oy + r0 * s["sa"],
                              ox + r * s["ca"], oy + r * s["sa"])
                b = (min(1.0, r / 320.0) ** 0.8) * s["br"] * fs * dust
                b = round(b * 20) / 20.0
                sf(s["it"], mix(BASE, HOT if (v > 300 and s["col"] == ACC) else s["col"],
                                0.06 + 0.88 * b))

            fh = smooth((t - 0.3) / 1.2)
            vis("g_hex", fh > 0.01)
            if fh > 0.01:
                hcol = mix(BASE, ACC, (0.14 if dark else 0.24) * fh)
                for hc in hexcols:
                    if now >= hc["next"]:
                        hc["next"] = now + 0.12
                        hc["lines"][random.randrange(20)] = "%02X %02X" % (
                            random.randint(0, 255), random.randint(0, 255))
                        canvas.itemconfigure(hc["it"], text="\n".join(hc["lines"]))
                    y = h - ((hc["off"] + hc["sp"] * t) % (h + 300))
                    canvas.coords(hc["it"], hc["x"], y)
                    sf(hc["it"], hcol)

            fg_ = smooth((t - 0.2) / 1.2)
            lvl = fg_ * (0.55 + 0.45 * pulse)
            if t > T_DONE:
                lvl += 0.45 * math.exp(-4.0 * (t - T_DONE))
            lvl = clamp(lvl)
            vis("g_glow", fg_ > 0.01)
            if has_pil and st["glow_frames"]:
                gi = int(lvl * (N_GLOW - 1) + 0.5)
                if gi != st["glow_idx"]:
                    st["glow_idx"] = gi
                    canvas.itemconfigure(glow_item, image=st["glow_frames"][gi])
                canvas.coords(glow_item, cx, cy)
            else:
                for i, it in enumerate(glow_ovals):
                    sf(it, mix(BASE, ACC, lvl * (0.012 + 0.016 * i)))

            f_disc = smooth((t - 0.25) / 0.9)
            vis("g_disc", f_disc > 0.01)
            sf(disc, mix(BASE, CARD, f_disc * (0.55 if dark else 0.72)))
            so(disc, mix(BASE, P, f_disc * 0.32))

            f_rd = smooth((t - 1.0) / 0.9)
            vis("g_ringd", f_rd > 0.01)
            so(ring_d, mix(BASE, ACC2, f_rd * 0.22))
            f_rc = smooth((t - 0.9) / 0.9)
            vis("g_ringc", f_rc > 0.01)
            so(ring_c0, mix(BASE, ACC2, f_rc * 0.14))

            f_ra = smooth((t - 0.5) / 0.9)
            vis("g_ringa", f_ra > 0.01)
            angA = 90 * t + 340 * (1 - math.exp(-1.5 * t))
            for i, it in enumerate(ringA):
                canvas.itemconfigure(it, start=(-angA + 180 * i) % 360)
                so(it, mix(BASE, P, f_ra))
            f_rc2 = smooth((t - 1.0) / 0.9)
            angC = 60 * t + 200 * (1 - math.exp(-1.2 * t))
            for i, it in enumerate(ringC):
                canvas.itemconfigure(it, start=(angC + 120 * i) % 360)
                so(it, mix(BASE, ACC2, f_rc2 * 0.9))

            theta = (90 - t * 150) % 360
            f_fan = smooth((t - 1.3) / 0.8)
            f_tk = smooth((t - 0.7) / 0.9)
            vis("g_fan", f_fan > 0.01)
            vis("g_tick", f_tk > 0.01)
            disc_col = mix(BASE, CARD, f_disc * (0.55 if dark else 0.72))
            if f_fan > 0.01:
                for i, it in enumerate(fan):
                    a = 0.5 * ((1 - i / 16.0) ** 1.7) * f_fan
                    canvas.itemconfigure(it, start=(theta + i * 5) % 360)
                    sf(it, mix(disc_col, P, a))
            if f_tk > 0.01:
                tk_base = mix(BASE, DIM, 0.35 * f_tk)
                for i, it in enumerate(ticks):
                    d = ((i * 5) - theta) % 360
                    b = (1 - d / 80.0) ** 1.6 if d < 80 else 0.0
                    sf(it, mix(tk_base, HOT if dark else P, b * f_tk))

            f_cm = smooth((t - 1.2) / 0.8)
            vis("g_comet", f_cm > 0.01)
            if f_cm > 0.01:
                for cm in comets:
                    a0 = cm["a0"] + cm["sp"] * t
                    for m, d in enumerate(cm["dots"]):
                        ang = math.radians(a0 + m * 4.4 * (1 if cm["sp"] < 0 else -1))
                        px = cx + Rr * math.cos(ang)
                        py = cy - Rr * math.sin(ang)
                        rr = max(1.0, 3.8 - m * 0.34)
                        oval(d, px, py, rr)
                        a = ((1 - m / 9.0) ** 1.6) * f_cm
                        sf(d, mix(BASE, HOT if (m == 0 and dark) else cm["col"], a))

            pop = 1.0
            if t > T_DONE:
                pop += 0.07 * math.sin(math.pi * clamp((t - T_DONE) / 0.45))
            bs = (1 + 0.010 * math.sin(t * 2.4)) * pop if t > 1.8 else 1.0
            Ss = S * bs
            draw = eout((t - 0.55) / 1.2)
            vis("g_shline", draw > 0.002)
            if draw > 0.002:
                m_pts = max(2, min(n_r, int(n_r * draw) + 1))
                for wd, pair in sh_lines:
                    for it, path in ((pair[0], right), (pair[1], left)):
                        canvas.coords(it, *flat(path[:m_pts], Ss, cx, cy))
                    if wd == 14:
                        col = mix(BASE, P, 0.10 + 0.04 * pulse)
                    elif wd == 7:
                        col = mix(BASE, P, 0.24 + 0.06 * pulse)
                    else:
                        col = mix(BASE, P if draw < 1 else mix(P, HOT, 0.25 * pulse), 1.0)
                    for it in pair:
                        sf(it, col)
            f_fill = smooth((t - 1.5) / 0.8)
            vis("g_shfill", f_fill > 0.01)
            if f_fill > 0.01:
                canvas.coords(sh_fill, *flat(SH, Ss * 0.985, cx, cy))
                sf(sh_fill, mix(disc_col, CARD if dark else "#ffffff", f_fill * 0.9))
            f_logo = smooth((t - 1.85) / 0.7)
            vis("g_logo", f_logo > 0.01)
            if f_logo > 0.01:
                Sl = Ss * LOGO
                canvas.coords(logo_l, *flat(SH[n_r - 1:] + [SH[0]], Sl, cx, cy))
                canvas.coords(logo_r, *flat(SH[:n_r], Sl, cx, cy))
                sf(logo_l, mix(disc_col, P, f_logo))
                sf(logo_r, mix(disc_col, P, f_logo * 0.13))
                so(logo_r, mix(disc_col, P, f_logo))
                canvas.coords(logo_check, cx - Sl * 0.25, cy + Sl * 0.01,
                              cx - Sl * 0.06, cy + Sl * 0.18,
                              cx + Sl * 0.28, cy - Sl * 0.19)
                sf(logo_check, mix(disc_col, FG, f_logo))

            scan_on = 2.1 < t < T_DONE + 0.2
            vis("g_scan", scan_on)
            if scan_on:
                u = (t * 0.62) % 2.0
                u = u if u <= 1.0 else 2.0 - u
                yu = -1.2 + 2.42 * smooth(u)
                Sl = Ss * LOGO
                fade_s = smooth((t - 2.1) / 0.4) * (1 - smooth((t - T_DONE) / 0.2))
                for i, it in enumerate(scan_lines):
                    off = (-7, -3.5, 0)[i]
                    y2 = yu + (off / (Sl)) * (1 if u < 0.5 else 1)
                    hwv = half_width(clamp(y2, -1.19, 1.21)) * Sl * 0.94
                    py = cy + y2 * Sl
                    canvas.coords(it, cx - hwv, py, cx + hwv, py)
                    a = (0.22, 0.5, 1.0)[i] * fade_s
                    sf(it, mix(mix(disc_col, P, 0.4), SCAN, a))

            vis("g_title", t > T_TITLE - 0.3)
            if t > T_TITLE - 0.3:
                for i, L in enumerate(letters):
                    Ti = T_TITLE + 0.35 + i * 0.11
                    if t < Ti:
                        if now >= L["next"]:
                            L["ch"] = random.choice(GLYPHS)
                            L["next"] = now + 0.05
                        canvas.itemconfigure(L["it"], text=L["ch"])
                        sf(L["it"], mix(BASE, ACC, 0.55 * smooth((t - T_TITLE + 0.3) / 0.3)))
                        canvas.coords(L["it"], L["x"], L["y"])
                    else:
                        q = (t - Ti) / 0.55
                        canvas.itemconfigure(L["it"], text=title[i])
                        col = mix(HOT if dark else ACC, FG, smooth(q))
                        tw0 = T_TITLE + 0.35 + len(title) * 0.11 + 0.6
                        if t > tw0:
                            ph = ((t - tw0) % 2.6) / 2.6 * (len(title) + 3) - 1.5
                            bb = max(0.0, 1 - abs(i - ph) / 1.5) ** 2
                            col = mix(col, ACC if not dark else HOT, 0.55 * bb)
                        sf(L["it"], col)
                        canvas.coords(L["it"], L["x"], L["y"] + (1 - eout(q)) * 10)

            f_m = smooth((t - 2.7) / 0.8)
            vis("g_meta", f_m > 0.01)
            if f_m > 0.01:
                ly = G["meta_y"]
                ext = 78 * k * eout((t - 2.7) / 0.9)
                canvas.coords(meta_l, cx - ext, ly, cx - 9, ly)
                canvas.coords(meta_r, cx + 9, ly, cx + ext, ly)
                lc = mix(BASE, ACC, 0.85 * f_m)
                sf(meta_l, lc)
                sf(meta_r, lc)
                for it, px, rr in ((meta_d[0], cx, 3.4), (meta_d[1], cx - ext, 2.0),
                                   (meta_d[2], cx + ext, 2.0)):
                    oval(it, px, ly, rr * f_m)
                    sf(it, mix(BASE, ACC, f_m))
                sf(ver_item, mix(BASE, ACC2, f_m))
                sf(auth_item, mix(BASE, DIM, f_m))

            f_c = smooth((t - 0.4) / 0.8)
            vis("g_corner", f_c > 0.01)
            if f_c > 0.01:
                cc = mix(BASE, ACC, 0.55 * f_c)
                for it in corners:
                    sf(it, cc)
                sf(lab_l, mix(BASE, DIM, f_c * 0.9))
                sf(lab_r, mix(BASE, DIM, f_c * 0.9))

            p = prog_at(t)
            f_bar = smooth((t - 0.7) / 0.6)
            vis("g_bar", f_bar > 0.01)
            if f_bar > 0.01:
                filled = p / 100.0 * N_SEG
                off_col = mix(BASE, BORDER, 0.9 * f_bar)
                for i, it in enumerate(segs):
                    if i + 1 <= filled:
                        base_c = mix(ACC, ACC2, i / (N_SEG - 1.0))
                        if dm > 0:
                            base_c = mix(base_c, GRN, dm * 0.55)
                        head = max(0.0, 1 - (filled - i - 1) / 4.0) if t < T_DONE else 0.0
                        sf(it, mix(base_c, HOT, 0.65 * head * (0.6 + 0.4 * pulse)))
                    elif i < filled:
                        frac = filled - i
                        sf(it, mix(off_col, HOT if dark else ACC, 0.35 + 0.55 * frac))
                    else:
                        sf(it, off_col)

                if t >= T_DONE:
                    idx = len(statuses)
                    text_full = final_status
                else:
                    idx = min(len(statuses) - 1, int(p / (100.0 / len(statuses))))
                    text_full = statuses[idx]
                if idx != st["status_idx"]:
                    st["status_idx"] = idx
                    st["status_t0"] = t
                n = int((t - st["status_t0"]) * 60)
                shown = text_full[:n]
                blink = "▌" if int(t * 2.4) % 2 == 0 else " "
                if t >= T_DONE and n >= len(text_full):
                    blink = ""
                canvas.itemconfigure(status_item, text=shown + blink)
                canvas.itemconfigure(caret, text="●" if t >= T_DONE else "›")
                sc = mix(mix(DIM, FG, 0.4), GRN, dm)
                sf(status_item, mix(BASE, sc, f_bar))
                sf(caret, mix(BASE, mix(ACC, GRN, dm), f_bar))
                pv = 100 if t >= T_DONE else int(p)
                canvas.itemconfigure(pct_item, text=f"{pv}%")
                sf(pct_item, mix(BASE, mix(ACC, GRN, dm), f_bar))

            if T_DONE > t >= st["next_wave"]:
                st["next_wave"] += 1.35
                wid = canvas.create_oval(0, 0, 0, 0, outline=BASE, width=2, fill="")
                canvas.tag_lower(wid, "g_disc")
                waves.append({"id": wid, "t0": t, "dur": 1.9, "r0": Rd, "r1": 330 * k,
                              "w": 2, "col": ACC, "a": 0.55})
            if t >= T_DONE and not st["flash_done"]:
                st["flash_done"] = True
                for r1, dur, wdt, col, a in ((470 * k, 0.9, 5, HOT, 0.95),
                                             (380 * k, 1.3, 2, GRN, 0.8)):
                    wid = canvas.create_oval(0, 0, 0, 0, outline=BASE, width=wdt, fill="")
                    canvas.tag_lower(wid, "g_disc")
                    waves.append({"id": wid, "t0": t, "dur": dur, "r0": Rd, "r1": r1,
                                  "w": wdt, "col": col, "a": a})
            alive = []
            for wv in waves:
                u = (t - wv["t0"]) / wv["dur"]
                if u >= 1:
                    canvas.delete(wv["id"])
                    continue
                oval(wv["id"], cx, cy, wv["r0"] + (wv["r1"] - wv["r0"]) * eout(u))
                canvas.itemconfigure(wv["id"], outline=mix(BASE, wv["col"], wv["a"] * (1 - u) ** 1.5))
                alive.append(wv)
            waves[:] = alive

            if t >= T_WIPE:
                u = clamp((t - T_WIPE) / (T_END - T_WIPE))
                R = ein(u) * math.hypot(w, h) * 0.62 + 4
                if st["wipe_item"] is None:
                    st["wipe_item"] = canvas.create_oval(0, 0, 0, 0, fill=c["BG"],
                                                         outline=ACC, width=3)
                oval(st["wipe_item"], cx, cy, R)
                if u >= 0.97:
                    canvas.itemconfigure(st["wipe_item"], outline="")
            if t >= T_END:
                st["done"] = True
                self._splash_job = self.root.after(10, self._build_main)

        def tick():
            if st["done"]:
                return
            try:
                frame()
            except tk.TclError:
                st["done"] = True
                return
            except Exception:
                traceback.print_exc()
                st["done"] = True
                try:
                    self._splash_job = self.root.after(10, self._build_main)
                except Exception:
                    pass
                return
            if not st["done"]:
                self._splash_job = self.root.after(15, tick)

        relayout()
        st["t0"] = time.perf_counter()
        st["last"] = st["t0"]
        self._splash_job = self.root.after(30, tick)

    # ==================== MAIN ====================
    def _build_main(self):
        self._destroy_all()
        c = self.C
        self.root.configure(bg=c["BG"])
        self._setup_styles()
        self._build_titlebar()
        workspace = tk.Frame(self.root, bg=c["BG"])
        workspace.pack(fill="both", expand=True)
        self._build_navbar(workspace)
        self.content_wrap = tk.Frame(workspace, bg=c["BG"])
        self.content_wrap.pack(side="left", fill="both", expand=True)
        self.content_wrap.grid_rowconfigure(0, weight=1)
        self.content_wrap.grid_columnconfigure(0, weight=1)
        self.pages = {}
        self.pages["home"] = self._page_home()
        self.pages["log"] = self._page_log()
        self.pages["quarantine"] = self._page_quarantine()
        self.pages["repair"] = self._page_repair()
        self.pages["settings"] = self._page_settings()
        self.pages["premium"] = self._page_premium()
        self.pages["about"] = self._page_about()
        self._build_statusbar()
        self._restore_log()
        self.show_page(self.page)
        self._pulse_status()
        if not self.log_lines:
            self._log(self.T["welcome_log"], "purple")
            self._log("   " + self.T["welcome_author"], "dim")
            if self.current_user:
                self._log(f"   👤 {self.current_user}", "info")
            self._log_divider()
            if DEFENDER_EXE:
                self._log(self.T["def_found"], "ok")
            else:
                self._log(self.T["def_not_found"], "mal")
        if not DEFENDER_EXE:
            self._set_status(self.T["status_defender_missing"], c["RED"])
            for b in (self.btn_folder, self.btn_quick, self.btn_full, self.btn_file):
                b.set_enabled(False)
        else:
            self._set_status(self.T["status_ready"], c["FG_DIM"])
        if self.startup_scan:
            path = self.startup_scan
            self.startup_scan = None
            self.root.after(800, lambda: self._scan_specific_file(path))
        self.root.after(2000, lambda: self._check_for_updates(silent=True))
        self.root.after(100, self._show_in_taskbar)
        self.root.after(3000, self._start_protection_monitor)

    def _build_titlebar(self):
        c = self.C
        tb = tk.Frame(self.root, bg=c["TITLEBAR"], height=42)
        tb.pack(fill="x", side="top")
        tb.pack_propagate(False)
        line = tk.Canvas(tb, height=1, bg=c["TITLEBAR"], highlightthickness=0)
        line.pack(side="bottom", fill="x")
        line.bind("<Configure>", lambda e: (
            line.delete("all"),
            line.create_rectangle(0, 0, e.width, 1, fill=c["BORDER"], outline=c["BORDER"])
        ))
        left = tk.Frame(tb, bg=c["TITLEBAR"])
        left.pack(side="left", padx=14, pady=0, fill="y")
        icon_lbl = tk.Canvas(left, width=22, height=22, bg=c["TITLEBAR"],
                             highlightthickness=0)
        icon_lbl.pack(side="left", pady=10)
        draw_ui_icon(icon_lbl, "brand", c["ACCENT"])
        name_lbl = tk.Label(left, text=APP_NAME, bg=c["TITLEBAR"], fg=c["FG"],
                            font=("Segoe UI", 10, "bold"))
        name_lbl.pack(side="left", padx=(8, 0), pady=10)
        ver_lbl = tk.Label(left, text=f"· {APP_VERSION}", bg=c["TITLEBAR"],
                           fg=c["ACCENT_2"], font=("Cascadia Code", 8))
        ver_lbl.pack(side="left", padx=(6, 0), pady=10)
        author_lbl = tk.Label(left, text=f"· {APP_AUTHOR}", bg=c["TITLEBAR"],
                              fg=c["FG_DIM"], font=("Segoe UI", 9))
        author_lbl.pack(side="left", padx=(8, 0), pady=10)
        if is_admin():
            tk.Label(left, text="· 🛡 ADMIN", bg=c["TITLEBAR"], fg=c["GREEN"],
                     font=("Segoe UI", 8, "bold")).pack(side="left", padx=(8, 0), pady=10)
        if self.current_user:
            tk.Label(left, text=f"· 👤 {self.current_user}",
                     bg=c["TITLEBAR"], fg=c["ACCENT"],
                     font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 0), pady=10)
        if self.tier != "free":
            bg_ = c["ACCENT"]
            tk.Label(left, text="TESTER", bg=bg_, fg=c["ON_ACCENT"],
                     font=("Segoe UI", 7, "bold"), padx=6, pady=2
                     ).pack(side="left", padx=(10, 0), pady=10)
        btns = tk.Frame(tb, bg=c["TITLEBAR"])
        btns.pack(side="right", fill="y")
        self._tb_btn(btns, "—", self._minimize, c["FG_DIM"], c["YELLOW"])
        self._tb_btn(btns, "▢", self._toggle_maximize, c["FG_DIM"], c["GREEN"])
        self._tb_btn(btns, "✕", self._close, c["FG_DIM"], c["RED"])
        for w in (tb, left, icon_lbl, name_lbl, ver_lbl, author_lbl):
            w.bind("<Button-1>", self._drag_start)
            w.bind("<B1-Motion>", self._drag_move)
            w.bind("<Double-Button-1>", lambda e: self._toggle_maximize())

    def _tb_btn(self, parent, text, cmd, fg, hover):
        c = self.C
        lbl = tk.Label(parent, text=text, bg=c["TITLEBAR"], fg=fg,
                       font=("Segoe UI", 11, "bold"), width=4,
                       cursor="hand2", pady=10)
        lbl.pack(side="left")
        lbl.bind("<Button-1>", lambda e: cmd())
        lbl.bind("<Enter>", lambda e: lbl.configure(bg=hover, fg=c["ON_ACCENT"]))
        lbl.bind("<Leave>", lambda e: lbl.configure(bg=c["TITLEBAR"], fg=fg))
        return lbl

    def _drag_start(self, e):
        self._drag_data["x"] = e.x_root
        self._drag_data["y"] = e.y_root

    def _drag_move(self, e):
        if self._is_maximized:
            return
        dx = e.x_root - self._drag_data["x"]
        dy = e.y_root - self._drag_data["y"]
        self._drag_data["x"] = e.x_root
        self._drag_data["y"] = e.y_root
        self.root.geometry(f"+{self.root.winfo_x() + dx}+{self.root.winfo_y() + dy}")

    def _minimize(self):
        self.root.overrideredirect(False)
        self.root.iconify()
        self.root.bind("<Map>", self._on_restore)

    def _on_restore(self, event=None):
        if self.root.state() == "normal":
            self.root.overrideredirect(True)
            self.root.unbind("<Map>")

    def _toggle_maximize(self):
        if self._is_maximized:
            self.root.geometry(self._saved_geo)
            self._is_maximized = False
        else:
            self._saved_geo = self.root.geometry()
            w = self.root.winfo_screenwidth()
            h = self.root.winfo_screenheight()
            self.root.geometry(f"{w}x{h}+0+0")
            self._is_maximized = True

    def _close(self):
        self._hide_to_tray()

    def _hide_to_tray(self):
        if not HAS_TRAY or self.tray is None:
            if self.is_scanning:
                if not messagebox.askyesno(self.T["ask_full_title"], self.T["ask_close"]):
                    return
            self._save_config()
            self.root.destroy()
            return
        self.root.withdraw()
        if not self.tray_notified and self.tray:
            self.tray_notified = True
            try:
                self.tray.notify(self.T["tray_hint"], APP_NAME)
            except Exception:
                pass

    def _setup_tray(self):
        if not HAS_TRAY:
            return
        try:
            img = make_tray_image()
            menu = pystray.Menu(
                pystray.MenuItem(self.T["tray_open"], self._tray_show, default=True),
                pystray.MenuItem(self.T["tray_scan"], self._tray_quick_scan),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(self.T["tray_exit"], self._tray_quit))
            self.tray = pystray.Icon("SentryX", img, self.T["tray_tooltip"], menu)
            threading.Thread(target=self.tray.run, daemon=True).start()
        except Exception:
            self.tray = None

    def _tray_show(self, icon=None, item=None):
        self.root.after(0, self._restore_from_tray)

    def _restore_from_tray(self):
        try:
            self.root.deiconify()
            self.root.overrideredirect(True)
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass

    def _tray_quick_scan(self, icon=None, item=None):
        self.root.after(0, self._restore_from_tray)
        self.root.after(200, self.start_quick_scan)

    def _tray_quit(self, icon=None, item=None):
        if self.is_scanning:
            self.root.after(0, self._ask_quit)
            return
        self._do_quit()

    def _ask_quit(self):
        self.root.deiconify()
        self.root.overrideredirect(True)
        self.root.lift()
        if messagebox.askyesno(self.T["ask_full_title"], self.T["ask_close"]):
            self._do_quit()

    def _do_quit(self):
        self._stop_downloads_watcher()
        self._stop_protection_monitor()
        try:
            if self.tray:
                self.tray.stop()
        except Exception:
            pass
        self._save_config()
        try:
            self.root.after(0, self.root.destroy)
        except Exception:
            pass

    def _restart_app(self):
        self._stop_downloads_watcher()
        self._stop_protection_monitor()
        try:
            if self.tray:
                self.tray.stop()
        except Exception:
            pass
        try:
            self._save_config()
        except Exception:
            pass
        try:
            if getattr(sys, "frozen", False):
                subprocess.Popen([sys.executable])
            else:
                subprocess.Popen([_get_gui_python_executable(), os.path.abspath(__file__)],
                                 creationflags=CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
                                 close_fds=True)
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass
        os._exit(0)

    def _build_navbar(self, parent):
        c = self.C
        nav = tk.Frame(parent, bg=c["BG_2"], width=206)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        tk.Frame(parent, bg=c["BORDER"], width=1).pack(side="left", fill="y")
        brand = tk.Frame(nav, bg=c["BG_2"])
        brand.pack(fill="x", padx=14, pady=(19, 22))
        brand_icon = tk.Canvas(brand, width=30, height=30, bg=c["BG_2"],
                               highlightthickness=0)
        brand_icon.pack(side="left")
        draw_ui_icon(brand_icon, "brand", c["ACCENT"])
        brand_text = tk.Frame(brand, bg=c["BG_2"])
        brand_text.pack(side="left", padx=(9, 0))
        tk.Label(brand_text, text="SENTRYX", bg=c["BG_2"], fg=c["FG"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(brand_text, text="SECURITY CENTER", bg=c["BG_2"], fg=c["FG_DIM"],
                 font=("Segoe UI", 7)).pack(anchor="w", pady=(1, 0))
        tk.Label(nav, text="WORKSPACE" if self.lang == "en" else "РАБОЧАЯ ОБЛАСТЬ",
                 bg=c["BG_2"], fg=c["FG_DIM"], font=("Segoe UI", 7, "bold")
                 ).pack(anchor="w", padx=17, pady=(0, 8))
        tk.Frame(nav, bg=c["BORDER"], height=1).pack(fill="x", padx=14, pady=(0, 9))
        self.nav_tabs = {}
        items = [
            ("home", "", self.T["nav_home"]),
            ("log", "", self.T["nav_log"]),
            ("quarantine", "", self.T["nav_quarantine"]),
            ("repair", "", self.T["nav_repair"]),
            ("settings", "", self.T["nav_settings"]),
            ("premium", "", self.T["nav_premium"]),
            ("about", "", self.T["nav_about"]),
        ]
        for k, ic, lb in items:
            t = NavTab(nav, ic, lb, None, colors=c, key=k,
                       on_hover=self._nav_hover, on_leave=self._nav_leave,
                       on_click=self.show_page)
            t.pack(fill="x", padx=(9, 11), pady=2)
            self.nav_tabs[k] = t

    def _nav_hover(self, key):
        if key == self.page:
            return
        self.nav_tabs[key].set_hover(True)

    def _nav_leave(self, key):
        if key == self.page:
            return
        self.nav_tabs[key].set_hover(False)

    def _update_nav_active(self):
        for k, t in self.nav_tabs.items():
            t.set_active(k == self.page)

    def show_page(self, key):
        if key not in self.pages:
            return
        self.page = key
        for k, p in self.pages.items():
            if k == key:
                p.grid(row=0, column=0, sticky="nsew")
            else:
                p.grid_remove()
        self._update_nav_active()
        if key == "home":
            self._start_scene_animation()
        else:
            self._stop_scene_animation()

    def _build_scene_banner(self, parent):
        c = self.C
        scene = tk.Canvas(parent, height=142, bg=c["CARD"],
                          highlightthickness=1, highlightbackground=c["BORDER"])
        scene.pack(fill="x", pady=(0, 14))
        self._scene_canvas = scene
        scene.bind("<Configure>", self._schedule_scene_redraw, add="+")
        scene.bind("<ButtonPress-1>", self._wallpaper_drag_start, add="+")
        scene.bind("<B1-Motion>", self._wallpaper_drag_motion, add="+")
        scene.bind("<ButtonRelease-1>", self._wallpaper_drag_end, add="+")
        self._render_scene_banner()
        return scene

    def _schedule_scene_redraw(self, event=None):
        if self._scene_resize_job:
            try:
                self.root.after_cancel(self._scene_resize_job)
            except Exception:
                pass
        self._scene_resize_job = self.root.after(100, self._render_scene_banner)

    def _render_scene_banner(self):
        self._scene_resize_job = None
        canvas = self._scene_canvas
        if canvas is None or not canvas.winfo_exists():
            return
        w, h = canvas.winfo_width(), canvas.winfo_height()
        if w < 20 or h < 20:
            return
        c = self.C
        scene = VISUAL_SCENES[self.visual_scene]
        canvas.delete("all")
        self._scene_photo = None

        loaded = False
        if self.wallpaper_path and os.path.isfile(self.wallpaper_path):
            try:
                from PIL import Image as PImg, ImageOps, ImageTk as PTk
                image = PImg.open(self.wallpaper_path).convert("RGB")
                resampling = getattr(PImg, "Resampling", PImg)
                image = ImageOps.fit(
                    image, (w, h), method=resampling.LANCZOS,
                    centering=(self.wallpaper_focus_x, self.wallpaper_focus_y))
                tint = PImg.new("RGB", (w, h), scene["END"])
                image = PImg.blend(image, tint, 0.30)
                from PIL import ImageDraw
                veil = ImageDraw.Draw(image, "RGBA")
                veil_width = int(w * 0.68)
                for x in range(veil_width):
                    alpha = int(150 * (1 - x / max(1, veil_width)))
                    veil.line((x, 0, x, h), fill=(8, 15, 23, alpha))
                self._scene_photo = PTk.PhotoImage(image)
                canvas.create_image(0, 0, image=self._scene_photo, anchor="nw")
                loaded = True
            except Exception:
                try:
                    photo = tk.PhotoImage(file=self.wallpaper_path)
                    scale = max(1, math.ceil(max(photo.width() / w, photo.height() / h)))
                    if scale > 1:
                        photo = photo.subsample(scale, scale)
                    self._scene_photo = photo
                    canvas.create_image(w // 2, h // 2, image=photo, anchor="center")
                    loaded = True
                except Exception:
                    pass

        if not loaded:
            start = scene["START"]
            end = scene["END"]
            bands = 48
            for i in range(bands):
                x0 = int(w * i / bands)
                x1 = int(w * (i + 1) / bands) + 1
                canvas.create_rectangle(x0, 0, x1, h,
                                        fill=lerp_color(start, end, i / max(1, bands - 1)),
                                        outline="")
            canvas.create_oval(w * 0.61, -h * 1.1, w * 1.08, h * 1.9,
                               outline=scene["GLOW"], width=1)
            canvas.create_oval(w * 0.68, -h * 0.7, w * 1.0, h * 1.45,
                               outline=c["BORDER"], width=1)
            canvas.create_oval(w * 0.76, -h * 0.25, w * 0.95, h * 1.2,
                               outline=c["BORDER"], width=1)

        # Tk's stipple patterns look harsh in light mode; keep a clean dark panel
        # only for its low-capability image fallback.
        if loaded and not self._scene_photo.__class__.__module__.startswith("PIL"):
            canvas.create_rectangle(0, 0, w * 0.38, h, fill=scene["END"], outline="")
        canvas.create_text(24, 31, text="SENTRYX  /  VISUAL MODE",
                           fill="#d9e5ed", anchor="w",
                           font=("Segoe UI", 8, "bold"), tags="scene_text")
        scene_names = {
            "aurora": ("\u0421\u0435\u0432\u0435\u0440\u043d\u043e\u0435 \u0441\u0438\u044f\u043d\u0438\u0435", "Aurora"),
            "ocean": ("\u041e\u043a\u0435\u0430\u043d", "Ocean"),
            "forest": ("\u041b\u0435\u0441", "Forest"),
            "ember": ("\u0417\u0430\u043a\u0430\u0442", "Ember"),
            "arctic": ("\u0410\u0440\u043a\u0442\u0438\u043a\u0430", "Arctic"),
        }
        scene_name = scene_names[self.visual_scene][0 if self.lang == "ru" else 1]
        canvas.create_text(24, 66, text=scene_name, fill="#f3f7fa", anchor="w",
                           font=("Segoe UI", 23, "bold"), tags="scene_text")
        effect_names = {"off": "\u0411\u0435\u0437 \u044d\u0444\u0444\u0435\u043a\u0442\u0430" if self.lang == "ru" else "Still",
                        "snow": "\u0421\u043d\u0435\u0433" if self.lang == "ru" else "Snow",
                        "rain": "\u0414\u043e\u0436\u0434\u044c" if self.lang == "ru" else "Rain"}
        wallpaper_note = (os.path.basename(self.wallpaper_path)
                          if loaded and self.wallpaper_path
                          else ("\u0412\u044b\u0431\u0435\u0440\u0438 \u043e\u0431\u043e\u0438 \u0432 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430\u0445" if self.lang == "ru"
                                else "Choose a wallpaper in Settings"))
        canvas.create_text(25, h - 26,
                           text=f"{wallpaper_note}   |   {effect_names[self.scene_effect]}",
                           fill="#c8d5df", anchor="w", font=("Segoe UI", 9),
                           tags="scene_text")
        self._scene_particles = []
        if self.scene_effect != "off":
            count = 92 if self.scene_effect == "snow" else 84
            for _ in range(count):
                x, y = random.uniform(0, w), random.uniform(0, h)
                if self.scene_effect == "snow":
                    size = random.uniform(2.2, 5.0)
                    item = canvas.create_oval(x, y, x + size, y + size,
                                              fill=random.choice(("#ffffff", "#eaf5ff", "#d7e9f5")), outline="",
                                              tags="scene_particle")
                    speed = random.uniform(24, 58)
                else:
                    length = random.uniform(16, 32)
                    item = canvas.create_line(x, y, x - 3, y + length,
                                              fill=random.choice(("#c5e7f5", "#a5d5e9", "#ecf8ff")),
                                              width=1.4,
                                              tags="scene_particle")
                    speed = random.uniform(210, 340)
                    size = length
                self._scene_particles.append({"item": item, "x": x, "y": y,
                                              "speed": speed, "size": size,
                                              "phase": random.random() * math.tau})
        if self.page == "home":
            self._start_scene_animation()

    def _wallpaper_drag_start(self, event):
        if self.wallpaper_path and os.path.isfile(self.wallpaper_path):
            self._wallpaper_drag_point = (event.x, event.y)
            if self._scene_canvas and self._scene_canvas.winfo_exists():
                self._scene_canvas.configure(cursor="fleur")

    def _wallpaper_drag_motion(self, event):
        if self._wallpaper_drag_point is None or not self.wallpaper_path:
            return
        last_x, last_y = self._wallpaper_drag_point
        w = max(1, self._scene_canvas.winfo_width())
        h = max(1, self._scene_canvas.winfo_height())
        self.wallpaper_focus_x = min(1.0, max(0.0, self.wallpaper_focus_x - (event.x - last_x) / w))
        self.wallpaper_focus_y = min(1.0, max(0.0, self.wallpaper_focus_y - (event.y - last_y) / h))
        self._wallpaper_drag_point = (event.x, event.y)
        self._schedule_scene_redraw()

    def _wallpaper_drag_end(self, event=None):
        if self._wallpaper_drag_point is None:
            return
        self._wallpaper_drag_point = None
        if self._scene_canvas and self._scene_canvas.winfo_exists():
            self._scene_canvas.configure(cursor="")
        self._save_config()

    def _start_scene_animation(self):
        self._stop_scene_animation()
        if self.page != "home" or self.scene_effect == "off" or self._scene_canvas is None:
            return
        self._scene_last_frame = time.perf_counter()
        self._animate_scene()

    def _stop_scene_animation(self):
        if self._scene_after:
            try:
                self.root.after_cancel(self._scene_after)
            except Exception:
                pass
        self._scene_after = None

    def _animate_scene(self):
        canvas = self._scene_canvas
        if (canvas is None or not canvas.winfo_exists() or self.page != "home"
                or self.scene_effect == "off"):
            self._scene_after = None
            return
        now = time.perf_counter()
        dt = min(0.08, now - (self._scene_last_frame or now))
        self._scene_last_frame = now
        w, h = max(1, canvas.winfo_width()), max(1, canvas.winfo_height())
        snow = self.scene_effect == "snow"
        for p in self._scene_particles:
            p["y"] += p["speed"] * dt
            if snow:
                p["x"] += math.sin(now * 0.8 + p["phase"]) * 11 * dt
                size = p["size"]
                canvas.coords(p["item"], p["x"], p["y"], p["x"] + size, p["y"] + size)
            else:
                size = p["size"]
                p["x"] -= 78 * dt
                canvas.coords(p["item"], p["x"], p["y"], p["x"] - 3, p["y"] + size)
            if p["y"] > h + 24:
                p["y"] = -random.uniform(4, 35)
                p["x"] = random.uniform(0, w)
        self._scene_after = self.root.after(40, self._animate_scene)

    def set_visual_scene(self, scene):
        if scene not in VISUAL_SCENES or scene == self.visual_scene:
            return
        self.visual_scene = scene
        self._save_config()
        self._rebuild_preserve()

    def set_scene_effect(self, effect):
        if effect not in {"off", "snow", "rain"} or effect == self.scene_effect:
            return
        self.scene_effect = effect
        self._save_config()
        self._rebuild_preserve()

    def choose_wallpaper(self):
        path = filedialog.askopenfilename(
            title="\u0412\u044b\u0431\u0440\u0430\u0442\u044c \u043e\u0431\u043e\u0438" if self.lang == "ru" else "Choose wallpaper",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.webp *.bmp *.gif"), ("All files", "*.*")])
        if path:
            self.wallpaper_path = path
            self.wallpaper_focus_x = self.wallpaper_focus_y = 0.5
            self._save_config()
            self._rebuild_preserve()

    def clear_wallpaper(self):
        if not self.wallpaper_path:
            return
        self.wallpaper_path = ""
        self.wallpaper_focus_x = self.wallpaper_focus_y = 0.5
        self._save_config()
        self._rebuild_preserve()

    def _page_home(self):
        c = self.C
        page = tk.Frame(self.content_wrap, bg=c["BG"])
        outer_canvas = tk.Canvas(page, bg=c["BG"], highlightthickness=0)
        outer_scroll = ttk.Scrollbar(page, orient="vertical",
                                     style="Dark.Vertical.TScrollbar",
                                     command=outer_canvas.yview)
        outer_canvas.configure(yscrollcommand=outer_scroll.set)
        outer_scroll.pack(side="right", fill="y")
        outer_canvas.pack(side="left", fill="both", expand=True)
        wrap = tk.Frame(outer_canvas, bg=c["BG"])
        win = outer_canvas.create_window((0, 0), window=wrap, anchor="nw")

        def on_conf(e):
            try:
                outer_canvas.configure(scrollregion=outer_canvas.bbox("all"))
                outer_canvas.itemconfigure(win, width=outer_canvas.winfo_width())
            except Exception:
                pass
        wrap.bind("<Configure>", on_conf)
        outer_canvas.bind("<Configure>", on_conf)

        def _mw(event):
            try:
                outer_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except Exception:
                pass

        def _bind_wheel_recursive(widget):
            try:
                widget.bind("<MouseWheel>", _mw, add="+")
                for ch in widget.winfo_children():
                    _bind_wheel_recursive(ch)
            except Exception:
                pass

        def _on_enter(e):
            try:
                outer_canvas.bind_all("<MouseWheel>", _mw)
            except Exception:
                pass

        def _on_leave(e):
            try:
                outer_canvas.unbind_all("<MouseWheel>")
            except Exception:
                pass

        outer_canvas.bind("<Enter>", _on_enter)
        outer_canvas.bind("<Leave>", _on_leave)
        wrap.bind("<Enter>", _on_enter)
        wrap.bind("<Leave>", _on_leave)

        inner = tk.Frame(wrap, bg=c["BG"])
        inner.pack(fill="both", expand=True, padx=25, pady=20)
        self._build_scene_banner(inner)
        head = tk.Frame(inner, bg=c["BG"])
        head.pack(fill="x", pady=(0, 14))
        tk.Label(head, text=self.T["home_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(head, text=self.T["home_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

        last = self._get_last_scan()
        lc = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        lc.pack(fill="x", pady=(0, 14))
        li = tk.Frame(lc, bg=c["CARD"])
        li.pack(fill="x", padx=18, pady=12)
        tk.Label(li, text=self.T["last_scan_title"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        if last:
            res = last.get("result", "clean")
            th = last.get("threats", 0)
            if res == "danger" or th > 0:
                dc = c["RED"]
                st = self.T["last_scan_threats"].format(n=th)
            elif res == "stopped":
                dc = c["YELLOW"]
                st = self.T["hist_stopped"]
            else:
                dc = c["GREEN"]
                st = self.T["last_scan_clean"]
            tk.Label(li, text=f"{last['date']}   ·   {st}   ·   {last.get('duration',0)}s",
                     bg=c["CARD"], fg=c["FG"], font=("Cascadia Code", 9, "bold")
                     ).pack(side="right")
            tk.Label(li, text="●", bg=c["CARD"], fg=dc,
                     font=("Segoe UI", 12)).pack(side="right", padx=(8, 6))
        else:
            tk.Label(li, text=self.T["last_scan_none"], bg=c["CARD"], fg=c["FG_DIM"],
                     font=("Cascadia Code", 9)).pack(side="right")

        pc = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        pc.pack(fill="x", pady=(0, 14))
        pi = tk.Frame(pc, bg=c["CARD"])
        pi.pack(fill="x", padx=18, pady=14)
        tk.Label(pi, text=self.T["folder_label"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        row = tk.Frame(pi, bg=c["CARD"])
        row.pack(fill="x", pady=(8, 0))
        self.folder_var = tk.StringVar(value=self.folder_path)
        ew = tk.Frame(row, bg=c["INPUT"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        ew.pack(side="left", fill="x", expand=True)
        tk.Entry(ew, textvariable=self.folder_var, bg=c["INPUT"], fg=c["FG"],
                 insertbackground=c["ACCENT"], relief="flat", bd=0,
                 font=("Cascadia Code", 10)).pack(fill="x", padx=14, pady=10)
        RoundedButton(row, self.T["btn_browse"], self.choose_folder,
                      bg=c["CARD_2"], fg=c["FG"], hover_bg=c["BORDER"],
                      hover_fg=c["ACCENT"], width=130, height=40,
                      canvas_bg=c["CARD"]).pack(side="left", padx=(10, 0))

        br = tk.Frame(inner, bg=c["BG"])
        br.pack(fill="x", pady=(0, 8))
        self.btn_folder = RoundedButton(br, self.T["btn_folder"], self.start_folder_scan,
                                        bg=c["ACCENT"], fg=c["ON_ACCENT"],
                                        hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                                        hover_fg=c["ON_ACCENT"], width=210, height=48,
                                        canvas_bg=c["BG"])
        self.btn_folder.pack(side="left")
        self.btn_quick = RoundedButton(br, self.T["btn_quick"], self.start_quick_scan,
                                       bg=c["CARD_2"], fg=c["FG"],
                                       hover_bg=c["BORDER"], hover_fg=c["FG"],
                                       width=190, height=48,
                                       canvas_bg=c["BG"])
        self.btn_quick.pack(side="left", padx=(12, 0))
        self.btn_full = RoundedButton(br, self.T["btn_full"], self.start_full_scan,
                                      bg=c["CARD_2"], fg=c["FG"],
                                      hover_bg=c["BORDER"], hover_fg=c["FG"],
                                      width=190, height=48,
                                      canvas_bg=c["BG"])
        self.btn_full.pack(side="left", padx=(12, 0))
        self.btn_file = RoundedButton(br, self.T["btn_file"], self.start_file_scan,
                                      bg=c["CARD_2"], fg=c["FG"],
                                      hover_bg=c["BORDER"], hover_fg=c["ACCENT"],
                                      width=160, height=48, canvas_bg=c["BG"])
        self.btn_file.pack(side="left", padx=(12, 0))

        info = tk.Frame(inner, bg=c["BG"])
        info.pack(fill="x", pady=(10, 10))
        self._mini_card(info, "brand", self.T["mini_engine_t"], self.T["mini_engine_v"], c["ACCENT"])
        self._mini_card(info, "speed", self.T["mini_speed_t"], self.T["mini_speed_v"], c["GREEN"])
        self._mini_card(info, "privacy", self.T["mini_privacy_t"], self.T["mini_privacy_v"], c["ACCENT_2"])
        if self.tier == "tester":
            ti, tt, tc = "license", "TESTER", c["ACCENT"]
        else:
            ti, tt, tc = "license", "Free", c["YELLOW"]
        self._mini_card(info, ti, self.T["mini_license_t"], tt, tc)

        tk.Frame(inner, bg=c["BORDER"], height=1).pack(fill="x", pady=(18, 14))
        th = tk.Frame(inner, bg=c["BG"])
        th.pack(fill="x", pady=(0, 10))
        scan_icon = tk.Canvas(th, width=22, height=22, bg=c["BG"],
                              highlightthickness=0)
        scan_icon.pack(side="left")
        draw_ui_icon(scan_icon, "search", c["ACCENT"])
        tk.Label(th, text="Усиленная проверка" if self.lang == "ru" else "Threat scan",
                 bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 15, "bold")).pack(side="left", padx=(8, 0))
        tk.Label(th, text="Майнеры · Ратники · Стилеры · Автозагрузки · Порты · Планировщик",
                 bg=c["BG"], fg=c["FG_DIM"], font=("Segoe UI", 9)
                 ).pack(side="left", padx=(14, 0))
        tt_ = tk.Frame(inner, bg=c["BG"])
        tt_.pack(fill="x", pady=(0, 10))
        self.btn_scan_threats = RoundedButton(tt_,
                                              "Начать поиск" if self.lang == "ru" else "Start threat scan",
                                              self._start_threat_scan,
                                              bg=c["CARD_2"], fg=c["FG"],
                                              hover_bg=c["BORDER"], hover_fg=c["FG"],
                                              width=250, height=46, canvas_bg=c["BG"])
        self.btn_scan_threats.pack(side="left")
        self.threat_status = tk.Label(tt_, text="", bg=c["BG"], fg=c["FG_DIM"],
                                      font=("Cascadia Code", 9))
        self.threat_status.pack(side="left", padx=(15, 0))
        if not HAS_PSUTIL:
            self.threat_status.configure(
                text="ℹ  Установи pip install psutil для полной проверки",
                fg=c["YELLOW"])
        to = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"], height=340)
        to.pack(fill="x", pady=(4, 0))
        to.pack_propagate(False)
        self.threats_canvas = tk.Canvas(to, bg=c["CARD"], highlightthickness=0)
        self.threats_scroll = ttk.Scrollbar(to, orient="vertical",
                                            style="Dark.Vertical.TScrollbar",
                                            command=self.threats_canvas.yview)
        self.threats_canvas.configure(yscrollcommand=self.threats_scroll.set)
        self.threats_scroll.pack(side="right", fill="y")
        self.threats_canvas.pack(side="left", fill="both", expand=True)
        self.threats_container = tk.Frame(self.threats_canvas, bg=c["CARD"])
        self._threats_window = self.threats_canvas.create_window(
            (0, 0), window=self.threats_container, anchor="nw")

        def on_threat_conf(e):
            try:
                self.threats_canvas.configure(scrollregion=self.threats_canvas.bbox("all"))
                self.threats_canvas.itemconfigure(self._threats_window,
                                                  width=self.threats_canvas.winfo_width())
            except Exception:
                pass
        self.threats_container.bind("<Configure>", on_threat_conf)
        self.threats_canvas.bind("<Configure>", on_threat_conf)
        if self._last_threat_findings is not None:
            self.root.after(50, lambda: self._render_threats(self._last_threat_findings))
        else:
            self.root.after(50, self._render_threats_placeholder)
        self.root.after(100, lambda: _bind_wheel_recursive(page))
        return page

    def _mini_card(self, parent, icon, title, text, color):
        c = self.C
        card = tk.Frame(parent, bg=c["CARD"], highlightthickness=1,
                        highlightbackground=c["BORDER"])
        card.pack(side="left", fill="both", expand=True, padx=4)
        inner = tk.Frame(card, bg=c["CARD"])
        inner.pack(padx=14, pady=12, anchor="w")
        icon_canvas = tk.Canvas(inner, width=22, height=22, bg=c["CARD"],
                                highlightthickness=0)
        icon_canvas.pack(anchor="w")
        draw_ui_icon(icon_canvas, icon, color)
        tk.Label(inner, text=title, bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(6, 0))
        tk.Label(inner, text=text, bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")

    def _render_threats_placeholder(self):
        c = self.C
        if not hasattr(self, "threats_container"):
            return
        for w in self.threats_container.winfo_children():
            w.destroy()
        p = tk.Frame(self.threats_container, bg=c["CARD"])
        p.pack(fill="both", expand=True, pady=40)
        tk.Label(p, text="🛡", bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI Emoji", 34)).pack()
        tk.Label(p, text="Готов к проверке", bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 11, "bold")).pack(pady=(6, 2))
        tk.Label(p, text="Нажми «Начать поиск» выше",
                 bg=c["CARD"], fg=c["FG_DIM"], font=("Segoe UI", 9)).pack()

    def _start_threat_scan(self):
        if self.is_scanning:
            messagebox.showinfo(self.T["msg_wait"], self.T["msg_wait_text"])
            return
        try:
            self.btn_scan_threats.set_enabled(False)
        except Exception:
            pass
        self.threat_status.configure(text="⏳ Сканирую систему...", fg=self.C["ACCENT"])
        self._last_threat_findings = None
        if not hasattr(self, "threats_container"):
            return
        for w in self.threats_container.winfo_children():
            w.destroy()
        c = self.C
        ld = tk.Frame(self.threats_container, bg=c["CARD"])
        ld.pack(fill="both", expand=True, pady=40)
        tk.Label(ld, text="⏳", bg=c["CARD"], fg=c["ACCENT"],
                 font=("Segoe UI Emoji", 34)).pack()
        tk.Label(ld, text="Сканирую...", bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 11, "bold")).pack(pady=(6, 0))
        threading.Thread(target=self._threat_scan_worker, daemon=True).start()

    def _threat_scan_worker(self):
        try:
            findings = scan_threats()
        except Exception as e:
            self.root.after(0, lambda: self.threat_status.configure(
                text=f"❌ Ошибка: {e}", fg=self.C["RED"]))
            self.root.after(0, lambda: self.btn_scan_threats.set_enabled(True))
            return
        self.root.after(0, lambda: self._render_threats(findings))

    def _render_threats(self, findings, restore=False):
        c = self.C
        self._last_threat_findings = findings
        try:
            self.btn_scan_threats.set_enabled(True)
        except Exception:
            pass
        if not hasattr(self, "threats_container"):
            return
        for w in self.threats_container.winfo_children():
            w.destroy()
        if not findings:
            self.threat_status.configure(text="✅  Угроз не найдено", fg=c["GREEN"])
            ok = tk.Frame(self.threats_container, bg=c["CARD"])
            ok.pack(fill="both", expand=True, pady=40)
            tk.Label(ok, text="✅", bg=c["CARD"], fg=c["GREEN"],
                     font=("Segoe UI Emoji", 34)).pack()
            tk.Label(ok, text="Система чиста", bg=c["CARD"], fg=c["GREEN"],
                     font=("Segoe UI", 12, "bold")).pack(pady=(6, 2))
            tk.Label(ok, text="Угроз не обнаружено", bg=c["CARD"], fg=c["FG_DIM"],
                     font=("Segoe UI", 9)).pack()
            return
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda x: order.get(x.get("severity", "low"), 9))
        crit = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        self.threat_status.configure(
            text=f"⚠  Найдено: {len(findings)}  ·  критичных: {crit}  ·  серьёзных: {high}",
            fg=c["RED"] if crit else c["YELLOW"])
        h = tk.Frame(self.threats_container, bg=c["CARD"])
        h.pack(fill="x", padx=14, pady=(10, 6))
        tk.Label(h, text=f"НАЙДЕНО УГРОЗ: {len(findings)}",
                 bg=c["CARD"], fg=c["RED"], font=("Segoe UI", 9, "bold")).pack(side="left")
        for f in findings:
            self._render_threat_card(self.threats_container, f)

    def _render_threat_card(self, parent, f):
        c = self.C
        sev = f.get("severity", "low")
        col = {"critical": c["RED"], "high": c["RED"],
               "medium": c["YELLOW"], "low": c["ACCENT"]}.get(sev, c["FG"])
        icon = {"critical": "🚨", "high": "⚠", "medium": "⚡", "low": "ℹ"}.get(sev, "•")
        card = tk.Frame(parent, bg=c["CARD_2"], highlightthickness=1,
                        highlightbackground=col)
        card.pack(fill="x", padx=10, pady=5)
        inner = tk.Frame(card, bg=c["CARD_2"])
        inner.pack(fill="x", padx=14, pady=10)
        top = tk.Frame(inner, bg=c["CARD_2"])
        top.pack(fill="x")
        tk.Label(top, text=icon, bg=c["CARD_2"], fg=col,
                 font=("Segoe UI Emoji", 15)).pack(side="left")
        tk.Label(top, text=f["title"], bg=c["CARD_2"], fg=c["FG"],
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=(10, 0))
        tk.Label(top, text=f.get("category", "").upper(), bg=col, fg=c["ON_ACCENT"],
                 font=("Segoe UI", 7, "bold"), padx=6, pady=2).pack(side="right")
        tk.Label(inner, text=f["detail"], bg=c["CARD_2"], fg=c["FG_DIM"],
                 font=("Cascadia Code", 8), anchor="w", justify="left",
                 wraplength=760).pack(anchor="w", pady=(6, 8))
        btns = tk.Frame(inner, bg=c["CARD_2"])
        btns.pack(anchor="w")
        action = f.get("action_data", {}).get("action")
        if action == "kill":
            RoundedButton(btns, "⛔ Завершить процесс",
                          lambda d=f["action_data"]: self._threat_kill_process(d),
                          bg=c["RED"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["RED"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=190, height=32,
                          radius=10, font=("Segoe UI", 9, "bold"),
                          canvas_bg=c["CARD_2"]).pack(side="left", padx=(0, 6))
        if action == "startup":
            RoundedButton(btns, "🚫 Удалить из автозагрузки",
                          lambda d=f["action_data"]: self._threat_remove_startup(d),
                          bg=c["RED"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["RED"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=220, height=32,
                          radius=10, font=("Segoe UI", 9, "bold"),
                          canvas_bg=c["CARD_2"]).pack(side="left", padx=(0, 6))
        if action == "network":
            RoundedButton(btns, "⛔ Завершить процесс",
                          lambda d=f["action_data"]: self._threat_kill_pid(d.get("pid")),
                          bg=c["RED"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["RED"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=190, height=32,
                          radius=10, font=("Segoe UI", 9, "bold"),
                          canvas_bg=c["CARD_2"]).pack(side="left", padx=(0, 6))
        if action == "kill_task":
            RoundedButton(btns, self.T["sched_delete_task"],
                          lambda d=f["action_data"]: self._threat_delete_task(d.get("task_name")),
                          bg=c["RED"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["RED"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=200, height=32,
                          radius=10, font=("Segoe UI", 9, "bold"),
                          canvas_bg=c["CARD_2"]).pack(side="left", padx=(0, 6))

    def _threat_kill_process(self, data):
        self._threat_kill_pid(data.get("pid"))

    def _threat_kill_pid(self, pid):
        if not pid:
            return
        if not messagebox.askyesno("Завершение процесса", f"Завершить процесс PID {pid}?"):
            return
        try:
            if HAS_PSUTIL:
                psutil.Process(pid).kill()
            else:
                _run_hidden(["taskkill", "/F", "/PID", str(pid)], timeout=10)
            messagebox.showinfo("Готово", f"Процесс {pid} завершён")
            self._start_threat_scan()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _threat_remove_startup(self, data):
        source = data.get("source", "")
        name = data.get("name", "")
        if not messagebox.askyesno("Удаление из автозагрузки",
                                   f"Удалить запись «{name}» из {source}?"):
            return
        try:
            if "Реестр" in source:
                lb = source.replace("Реестр: ", "").strip()
                mp = {
                    "HKCU": (winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    "HKCU\\RunOnce": (winreg.HKEY_CURRENT_USER,
                                      r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    "HKLM": (winreg.HKEY_LOCAL_MACHINE,
                             r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    "HKLM\\RunOnce": (winreg.HKEY_LOCAL_MACHINE,
                                      r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                }
                if lb in mp:
                    root, path = mp[lb]
                    with winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS) as k:
                        winreg.DeleteValue(k, name)
                    messagebox.showinfo("Готово", "Запись удалена из реестра")
            elif "Startup" in source:
                if os.path.exists(name):
                    os.remove(name)
                elif os.path.exists(data.get("value", "")):
                    os.remove(data["value"])
                messagebox.showinfo("Готово", "Файл удалён из Startup")
            self._start_threat_scan()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _threat_delete_task(self, task_name):
        if not task_name:
            return
        if not messagebox.askyesno(self.T["sched_category"],
                                   self.T["sched_confirm"].format(name=task_name)):
            return
        try:
            rc, out, err = _run_hidden(["schtasks", "/delete", "/tn", task_name, "/f"],
                                        timeout=15)
            if rc == 0:
                messagebox.showinfo("Готово", self.T["sched_deleted"])
                self._start_threat_scan()
            else:
                messagebox.showerror("Ошибка", (err or out or "").strip()[:300])
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _page_log(self):
        c = self.C
        page = tk.Frame(self.content_wrap, bg=c["BG"])
        wrap = tk.Frame(page, bg=c["BG"])
        wrap.pack(fill="both", expand=True, padx=25, pady=20)
        h = tk.Frame(wrap, bg=c["BG"])
        h.pack(fill="x", pady=(0, 14))
        tk.Label(h, text=self.T["log_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(h, text=self.T["log_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))
        tools = tk.Frame(wrap, bg=c["BG"])
        tools.pack(fill="x", pady=(0, 10))
        search_wrap = tk.Frame(tools, bg=c["INPUT"], highlightthickness=1,
                               highlightbackground=c["BORDER"])
        search_wrap.pack(side="left", fill="x", expand=True)
        self.log_search_var = tk.StringVar(value=self.log_search)
        entry = tk.Entry(search_wrap, textvariable=self.log_search_var,
                         bg=c["INPUT"], fg=c["FG"], insertbackground=c["ACCENT"],
                         relief="flat", bd=0, font=("Segoe UI", 10))
        entry.pack(fill="x", padx=12, pady=9)
        if not self.log_search:
            entry.insert(0, self.T["log_search_ph"])
            entry.configure(fg=c["FG_DIM"])

            def on_focus_in(e):
                if entry.get() == self.T["log_search_ph"]:
                    entry.delete(0, "end")
                    entry.configure(fg=c["FG"])

            def on_focus_out(e):
                if not entry.get():
                    entry.insert(0, self.T["log_search_ph"])
                    entry.configure(fg=c["FG_DIM"])
            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)
        entry.bind("<KeyRelease>", lambda e: self._on_log_search_change())
        filters_row = tk.Frame(tools, bg=c["BG"])
        filters_row.pack(side="left", padx=(12, 0))
        filter_defs = [
            ("all", self.T["log_filter_all"], c["ACCENT"]),
            ("info", self.T["log_filter_info"], c["ACCENT"]),
            ("warn", self.T["log_filter_warn"], c["YELLOW"]),
            ("threat", self.T["log_filter_threat"], c["RED"]),
        ]
        self._log_filter_buttons = {}
        for key, label, color in filter_defs:
            active = (self.log_filter == key)
            btn = RoundedButton(
                filters_row, label,
                lambda k=key: self._set_log_filter(k),
                bg=color if active else c["CARD_2"],
                fg=c["ON_ACCENT"] if active else c["FG"],
                hover_bg=color if active else c["BORDER"],
                hover_fg=c["ON_ACCENT"] if active else color,
                width=110, height=36, radius=10,
                font=("Segoe UI", 9, "bold"), canvas_bg=c["BG"])
            btn.pack(side="left", padx=3)
            self._log_filter_buttons[key] = (btn, color)
        card = tk.Frame(wrap, bg=c["CARD"], highlightthickness=1,
                        highlightbackground=c["BORDER"])
        card.pack(fill="both", expand=True)
        lh = tk.Frame(card, bg=c["CARD"])
        lh.pack(fill="x", padx=18, pady=(14, 0))
        tk.Label(lh, text=self.T["log_events"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        self.log_counter_label = tk.Label(lh, text="", bg=c["CARD"], fg=c["FG_DIM"],
                                          font=("Cascadia Code", 8))
        self.log_counter_label.pack(side="right")
        lc = tk.Frame(card, bg=c["CARD"])
        lc.pack(fill="both", expand=True, padx=8, pady=(10, 12))
        sc = ttk.Scrollbar(lc, orient="vertical", style="Dark.Vertical.TScrollbar")
        sc.pack(side="right", fill="y")
        self.log = tk.Text(lc, bg=c["CARD"], fg=c["FG"],
                           font=("Cascadia Code", 9), relief="flat", bd=0,
                           wrap="word", insertbackground=c["CARD"], padx=12, pady=8,
                           highlightthickness=0, selectbackground=c["BORDER"],
                           selectforeground=c["FG"], yscrollcommand=sc.set,
                           takefocus=0)
        self.log.pack(side="left", fill="both", expand=True)
        sc.configure(command=self.log.yview)
        for t, col in [("mal", c["RED"]), ("ok", c["GREEN"]), ("warn", c["YELLOW"]),
                       ("info", c["ACCENT"]), ("dim", c["FG_DIM"]),
                       ("purple", c["ACCENT_2"])]:
            self.log.tag_config(t, foreground=col)
        self.log.tag_config("bold", font=("Cascadia Code", 9, "bold"))
        self.log.configure(state="disabled")
        return page

    def _on_log_search_change(self):
        val = self.log_search_var.get()
        if val == self.T["log_search_ph"]:
            self.log_search = ""
        else:
            self.log_search = val.strip()
        self._render_filtered_log()

    def _set_log_filter(self, key):
        self.log_filter = key
        c = self.C
        for k, (btn, color) in self._log_filter_buttons.items():
            active = (k == key)
            btn.bg = color if active else c["CARD_2"]
            btn.fg = c["ON_ACCENT"] if active else c["FG"]
            btn.hover_bg = color if active else c["BORDER"]
            btn.hover_fg = c["ON_ACCENT"] if active else color
            btn._draw(btn.bg, btn.fg)
        self._render_filtered_log()

    def _log_matches_filter(self, text, tag):
        f = self.log_filter
        if f == "all":
            return True
        if f == "info":
            return tag in ("info", "purple", None, "bold") or tag is None
        if f == "warn":
            return tag in ("warn", "dim")
        if f == "threat":
            return tag == "mal"
        return True

    def _render_filtered_log(self):
        if not hasattr(self, "log") or not self.log.winfo_exists():
            return
        search = self.log_search.lower()
        shown = 0
        total = len(self.log_lines)
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        for text, tag in self.log_lines:
            if not self._log_matches_filter(text, tag):
                continue
            if search and search not in text.lower():
                continue
            self.log.insert("end", text + "\n", tag)
            shown += 1
        if total == 0:
            self.log.insert("end", self.T["log_empty"] + "\n", "dim")
        elif shown == 0:
            self.log.insert("end", self.T["log_nothing_found"] + "\n", "dim")
        self.log.see("end")
        self.log.configure(state="disabled")
        try:
            self.log_counter_label.configure(text=f"{shown} / {total}")
        except Exception:
            pass

    def _page_quarantine(self):
        c = self.C
        page = tk.Frame(self.content_wrap, bg=c["BG"])
        wrap = tk.Frame(page, bg=c["BG"])
        wrap.pack(fill="both", expand=True, padx=25, pady=20)
        h = tk.Frame(wrap, bg=c["BG"])
        h.pack(fill="x", pady=(0, 14))
        tk.Label(h, text=self.T["quar_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(h, text=self.T["quar_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))
        self.quar_container = tk.Frame(wrap, bg=c["BG"])
        self.quar_container.pack(fill="both", expand=True)
        self._render_quarantine()
        return page

    def _render_quarantine(self):
        c = self.C
        if not hasattr(self, "quar_container"):
            return
        for w in self.quar_container.winfo_children():
            w.destroy()
        files = quarantine_list()
        if not files:
            e = tk.Frame(self.quar_container, bg=c["CARD"], highlightthickness=1,
                         highlightbackground=c["BORDER"])
            e.pack(fill="both", expand=True)
            i = tk.Frame(e, bg=c["CARD"])
            i.place(relx=0.5, rely=0.5, anchor="center")
            tk.Label(i, text="🔒", bg=c["CARD"], fg=c["FG_DIM"],
                     font=("Segoe UI Emoji", 36)).pack()
            tk.Label(i, text=self.T["quar_empty"], bg=c["CARD"], fg=c["FG_DIM"],
                     font=("Segoe UI", 11)).pack(pady=(8, 0))
            return
        for f in files:
            row = tk.Frame(self.quar_container, bg=c["CARD"], highlightthickness=1,
                           highlightbackground=c["BORDER"])
            row.pack(fill="x", pady=4)
            i = tk.Frame(row, bg=c["CARD"])
            i.pack(fill="x", padx=16, pady=12)
            left = tk.Frame(i, bg=c["CARD"])
            left.pack(side="left", fill="x", expand=True)
            tk.Label(left, text="📄 " + f["name"], bg=c["CARD"], fg=c["FG"],
                     font=("Segoe UI", 10, "bold"), anchor="w").pack(anchor="w")
            tk.Label(left, text=f"↳ {f['original_path']}", bg=c["CARD"],
                     fg=c["FG_DIM"], font=("Cascadia Code", 8), anchor="w"
                     ).pack(anchor="w", pady=(2, 0))
            tk.Label(left, text="🕒 " + f["date"], bg=c["CARD"], fg=c["FG_DIM"],
                     font=("Segoe UI", 8), anchor="w").pack(anchor="w", pady=(2, 0))
            rb = tk.Frame(i, bg=c["CARD"])
            rb.pack(side="right")
            fid = f["id"]
            RoundedButton(rb, self.T["quar_restore"],
                          lambda ii=fid: self._quar_restore(ii),
                          bg=c["GREEN"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=140, height=38,
                          canvas_bg=c["CARD"]).pack(side="left", padx=4)
            RoundedButton(rb, self.T["quar_delete"],
                          lambda ii=fid: self._quar_delete(ii),
                          bg=c["RED"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["RED"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=110, height=38,
                          canvas_bg=c["CARD"]).pack(side="left", padx=4)

    def _quar_restore(self, fid):
        if not messagebox.askyesno(self.T["quar_title"], self.T["quar_confirm_restore"]):
            return
        if quarantine_restore(fid):
            messagebox.showinfo(self.T["quar_title"], self.T["quar_restored"])
            self._render_quarantine()
        else:
            messagebox.showerror(self.T["err_title"], "Ошибка восстановления")

    def _quar_delete(self, fid):
        if not messagebox.askyesno(self.T["quar_title"], self.T["quar_confirm_delete"]):
            return
        if quarantine_delete(fid):
            self._render_quarantine()

    # ==================== REPAIR PAGE ====================
    def _page_repair(self):
        c = self.C
        ru = (self.lang == "ru")
        page = tk.Frame(self.content_wrap, bg=c["BG"])

        canvas = tk.Canvas(page, bg=c["BG"], highlightthickness=0)
        scroll = ttk.Scrollbar(page, orient="vertical",
                               style="Dark.Vertical.TScrollbar", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        wrap = tk.Frame(canvas, bg=c["BG"])
        win = canvas.create_window((0, 0), window=wrap, anchor="nw")

        def on_conf(e):
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
                canvas.itemconfigure(win, width=canvas.winfo_width())
            except Exception:
                pass
        wrap.bind("<Configure>", on_conf)
        canvas.bind("<Configure>", on_conf)

        def _mw(event):
            try:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except Exception:
                pass
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _mw))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        inner = tk.Frame(wrap, bg=c["BG"])
        inner.pack(fill="both", expand=True, padx=25, pady=20)

        head = tk.Frame(inner, bg=c["BG"])
        head.pack(fill="x", pady=(0, 14))
        tk.Label(head, text=("Целостность системы" if ru else "System integrity"),
                 bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(head,
                 text=("Восстановление системных файлов, точки восстановления, бэкап автозагрузки"
                       if ru else
                       "System files repair, restore points, autorun backup"),
                 bg=c["BG"], fg=c["FG_DIM"], font=("Segoe UI", 10)
                 ).pack(anchor="w", pady=(2, 0))

        if not is_admin():
            warn = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                            highlightbackground=c["YELLOW"])
            warn.pack(fill="x", pady=(0, 14))
            wi = tk.Frame(warn, bg=c["CARD"])
            wi.pack(fill="x", padx=18, pady=14)
            tk.Label(wi, text="⚠", bg=c["CARD"], fg=c["YELLOW"],
                     font=("Segoe UI Emoji", 16)).pack(side="left")
            col = tk.Frame(wi, bg=c["CARD"])
            col.pack(side="left", padx=(12, 0), fill="x", expand=True)
            tk.Label(col,
                     text=("Приложение запущено БЕЗ прав администратора" if ru
                           else "Application is NOT running as administrator"),
                     bg=c["CARD"], fg=c["YELLOW"],
                     font=("Segoe UI", 10, "bold")).pack(anchor="w")
            tk.Label(col,
                     text=("SFC, DISM и восстановление реестра требуют прав администратора. "
                           "Закрой приложение и запусти от имени администратора."
                           if ru else
                           "SFC, DISM and registry restore require administrator rights."),
                     bg=c["CARD"], fg=c["FG_DIM"], font=("Segoe UI", 8),
                     wraplength=760, justify="left").pack(anchor="w", pady=(2, 0))

        def make_tool_card(parent, title, desc, buttons):
            card = tk.Frame(parent, bg=c["CARD"], highlightthickness=1,
                            highlightbackground=c["BORDER"])
            card.pack(fill="x", pady=(0, 12))
            i = tk.Frame(card, bg=c["CARD"])
            i.pack(fill="x", padx=18, pady=16)
            tk.Label(i, text=title.upper(), bg=c["CARD"], fg=c["FG_DIM"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(i, text=desc, bg=c["CARD"], fg=c["FG"],
                     font=("Segoe UI", 10), justify="left",
                     wraplength=820).pack(anchor="w", pady=(6, 12))
            row = tk.Frame(i, bg=c["CARD"])
            row.pack(anchor="w")
            for label, color, cb in buttons:
                RoundedButton(row, label, cb,
                              bg=color, fg=c["ON_ACCENT"],
                              hover_bg=lerp_color(color, "#ffffff", 0.25),
                              hover_fg=c["ON_ACCENT"],
                              width=240, height=44,
                              font=("Segoe UI", 10, "bold"),
                              canvas_bg=c["CARD"]).pack(side="left", padx=(0, 10))
            return card

        make_tool_card(
            inner,
            "🔧 SFC — Проверка системных файлов" if ru else "🔧 SFC — System File Checker",
            ("Сканирует все защищённые системные файлы Windows и восстанавливает "
             "повреждённые/удалённые из резервного кэша Microsoft.\n"
             "⏱ Занимает 5–15 минут. Решает: пропавшие DLL, подменённые системные утилиты, "
             "сломанный explorer.exe."
             if ru else
             "Scans all protected Windows system files and restores damaged/deleted ones "
             "from Microsoft's backup cache.\n⏱ Takes 5–15 min."),
            [("🔧  Запустить SFC" if ru else "🔧  Run SFC", c["ACCENT"], self._repair_run_sfc)]
        )

        make_tool_card(
            inner,
            "🛠 DISM — Восстановление образа системы" if ru else "🛠 DISM — Image restore",
            ("Скачивает свежую копию системного образа с серверов Microsoft и "
             "заменяет повреждённые компоненты. Нужен если SFC не справился.\n"
             "⏱ Занимает 10–30 минут. Требуется интернет."
             if ru else
             "Downloads a fresh copy of the system image from Microsoft servers and "
             "replaces corrupted components.\n⏱ Takes 10–30 min. Requires internet."),
            [("🛠  Запустить DISM" if ru else "🛠  Run DISM", c["ACCENT_2"], self._repair_run_dism)]
        )

        make_tool_card(
            inner,
            "🔓 Разблокировка Windows" if ru else "🔓 Windows access recovery",
            ("Сохранит резервную копию настроек, восстановит стандартный вход в Windows, "
             "снимет известные блокировки диспетчера задач, реестра, командной строки и меню питания, "
             "попробует включить отключённые клавиатуру/мышь и восстановить системные файлы sethc/utilman.\n"
             "Потребуются права администратора. Изменения политик будут записаны в резервную копию."
             if ru else
             "Backs up affected settings, restores the standard Windows logon shell, removes common "
             "Task Manager/Registry/Command Prompt/shutdown-menu restrictions, attempts to enable "
             "disabled keyboard and mouse devices, and repairs sethc/utilman system files.\n"
             "Administrator rights are required; original registry values are saved first."),
            [("🔓 Восстановить доступ" if ru else "🔓 Restore access",
              c["GREEN"], self._repair_unlock_windows)]
        )

        make_tool_card(
            inner,
            "💾 Точки восстановления Windows" if ru else "💾 Windows Restore Points",
            ("Создаёт точку восстановления — снимок реестра и системных файлов. "
             "Если что-то сломается — откатишь систему на 5 минут назад.\n"
             "⚠ Работает только если защита системы включена в Windows."
             if ru else
             "Creates a Restore Point — snapshot of registry and system files."),
            [
                ("💾  Создать точку" if ru else "💾  Create point",
                 c["GREEN"], self._repair_create_point),
                ("⏮  Открыть восстановление" if ru else "⏮  Open restore",
                 c["YELLOW"], self._repair_open_rstrui),
                ("📋  Список точек" if ru else "📋  List points",
                 c["CARD_2"], self._repair_list_points),
            ]
        )

        make_tool_card(
            inner,
            "🚀 Резервная копия автозагрузки" if ru else "🚀 Autorun backup",
            ("Сохраняет все записи Run/RunOnce (HKCU + HKLM) в JSON-файл в папке данных. "
             "Если вирус убрал автозапуск программ — восстановишь одним кликом.\n"
             "💡 Делай бэкап когда система чистая."
             if ru else
             "Saves all Run/RunOnce entries to a JSON file. Restore one-click if malware "
             "wipes your startup."),
            [
                ("📤  Создать бэкап" if ru else "📤  Backup",
                 c["ACCENT"], self._repair_backup_autorun),
                ("📥  Восстановить" if ru else "📥  Restore",
                 c["GREEN"], self._repair_restore_autorun),
                ("📂  Открыть папку" if ru else "📂  Open folder",
                 c["CARD_2"], lambda: self._open_folder(repair_backup_dir())),
            ]
        )

        log_card = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                            highlightbackground=c["BORDER"])
        log_card.pack(fill="both", expand=True, pady=(6, 0))
        lh = tk.Frame(log_card, bg=c["CARD"])
        lh.pack(fill="x", padx=18, pady=(14, 0))
        tk.Label(lh, text=("ЛОГ ВОССТАНОВЛЕНИЯ" if ru else "REPAIR LOG"),
                 bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        self.repair_status_lbl = tk.Label(lh, text="", bg=c["CARD"], fg=c["FG_DIM"],
                                          font=("Cascadia Code", 8))
        self.repair_status_lbl.pack(side="right")

        lc = tk.Frame(log_card, bg=c["CARD"])
        lc.pack(fill="both", expand=True, padx=8, pady=(10, 12))
        sc2 = ttk.Scrollbar(lc, orient="vertical", style="Dark.Vertical.TScrollbar")
        sc2.pack(side="right", fill="y")
        self.repair_log = tk.Text(
            lc, bg=c["CARD"], fg=c["FG"],
            font=("Cascadia Code", 9), relief="flat", bd=0,
            wrap="word", insertbackground=c["CARD"], padx=12, pady=8,
            highlightthickness=0, selectbackground=c["BORDER"],
            selectforeground=c["FG"], yscrollcommand=sc2.set, height=14,
            takefocus=0)
        self.repair_log.pack(side="left", fill="both", expand=True)
        sc2.configure(command=self.repair_log.yview)
        for t, col in [("ok", c["GREEN"]), ("warn", c["YELLOW"]),
                       ("err", c["RED"]), ("info", c["ACCENT"]),
                       ("dim", c["FG_DIM"]), ("bold", c["FG"])]:
            self.repair_log.tag_config(t, foreground=col)
        self.repair_log.tag_config("bold", font=("Cascadia Code", 9, "bold"))
        self.repair_log.configure(state="disabled")

        self._repair_log(("Готово. Выбери инструмент выше." if ru
                          else "Ready. Choose a tool above."), "dim")
        return page

    def _repair_log(self, text, tag=None):
        if not hasattr(self, "repair_log") or not self.repair_log.winfo_exists():
            return
        self.repair_log.configure(state="normal")
        self.repair_log.insert("end", text + "\n", tag)
        self.repair_log.see("end")
        self.repair_log.configure(state="disabled")

    def _open_folder(self, path):
        try:
            os.startfile(path)
        except Exception as e:
            self._repair_log(f"[error] {e}", "err")

    def _repair_set_status(self, text, color=None):
        if not hasattr(self, "repair_status_lbl"):
            return
        if color is None:
            color = self.C["FG_DIM"]
        try:
            self.repair_status_lbl.configure(text=text, fg=color)
        except Exception:
            pass

    def _open_progress_dialog(self, title, subtitle="", icon="🔧"):
        c = self.C
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=c["BG"])
        dlg.transient(self.root)
        dlg.resizable(True, True)
        w, h = 640, 540
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
        dlg.geometry(f"{w}x{h}+{x}+{y}")
        dlg.minsize(500, 400)

        state = {"cancelled": False, "finished": False, "dlg": dlg}

        head = tk.Frame(dlg, bg=c["BG"])
        head.pack(fill="x", padx=20, pady=(18, 6))
        tk.Label(head, text=icon, bg=c["BG"], fg=c["ACCENT"],
                 font=("Segoe UI Emoji", 22)).pack(side="left")
        ht = tk.Frame(head, bg=c["BG"])
        ht.pack(side="left", padx=(10, 0))
        tk.Label(ht, text=title, bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        if subtitle:
            tk.Label(ht, text=subtitle, bg=c["BG"], fg=c["FG_DIM"],
                     font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

        prog_card = tk.Frame(dlg, bg=c["CARD"], highlightthickness=1,
                             highlightbackground=c["BORDER"])
        prog_card.pack(fill="x", padx=20, pady=(8, 10))
        pi = tk.Frame(prog_card, bg=c["CARD"])
        pi.pack(fill="x", padx=16, pady=14)
        status_lbl = tk.Label(pi, text="Запуск...", bg=c["CARD"], fg=c["ACCENT"],
                              font=("Cascadia Code", 10, "bold"), anchor="w")
        status_lbl.pack(fill="x")
        pct_lbl = tk.Label(pi, text="0%", bg=c["CARD"], fg=c["FG_DIM"],
                           font=("Cascadia Code", 9), anchor="e")
        pct_lbl.pack(fill="x", pady=(2, 4))
        pbar = ttk.Progressbar(pi, style="Product.Horizontal.TProgressbar",
                               mode="determinate", maximum=100, value=0)
        pbar.pack(fill="x")

        log_card = tk.Frame(dlg, bg=c["CARD"], highlightthickness=1,
                            highlightbackground=c["BORDER"])
        log_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        lc = tk.Frame(log_card, bg=c["CARD"])
        lc.pack(fill="both", expand=True, padx=8, pady=8)
        sc = ttk.Scrollbar(lc, orient="vertical", style="Dark.Vertical.TScrollbar")
        sc.pack(side="right", fill="y")
        log_widget = tk.Text(lc, bg=c["CARD"], fg=c["FG"],
                             font=("Cascadia Code", 9), relief="flat", bd=0,
                             wrap="word", padx=12, pady=8,
                             highlightthickness=0, selectbackground=c["BORDER"],
                             selectforeground=c["FG"], yscrollcommand=sc.set,
                             takefocus=0)
        log_widget.pack(side="left", fill="both", expand=True)
        sc.configure(command=log_widget.yview)
        for t, col in [("ok", c["GREEN"]), ("warn", c["YELLOW"]),
                       ("err", c["RED"]), ("info", c["ACCENT"]),
                       ("dim", c["FG_DIM"]), ("bold", c["FG"])]:
            log_widget.tag_config(t, foreground=col)
        log_widget.tag_config("bold", font=("Cascadia Code", 9, "bold"))
        log_widget.configure(state="disabled")

        btns = tk.Frame(dlg, bg=c["BG"])
        btns.pack(fill="x", padx=20, pady=(0, 18))
        close_holder = tk.Frame(btns, bg=c["BG"])
        close_holder.pack(side="right")

        def _log(line, tag=None):
            def upd():
                try:
                    if not log_widget.winfo_exists():
                        return
                    log_widget.configure(state="normal")
                    log_widget.insert("end", line + "\n", tag)
                    log_widget.see("end")
                    log_widget.configure(state="disabled")
                except Exception:
                    pass
            try:
                self.root.after(0, upd)
            except Exception:
                pass

        def _set_status(text, color=None):
            def upd():
                try:
                    status_lbl.configure(
                        text=text,
                        fg=color if color is not None else c["ACCENT"])
                except Exception:
                    pass
            try:
                self.root.after(0, upd)
            except Exception:
                pass

        def _set_progress(pct):
            def upd():
                try:
                    p = max(0, min(100, int(pct)))
                    pbar.configure(value=p)
                    pct_lbl.configure(text=f"{p}%")
                except Exception:
                    pass
            try:
                self.root.after(0, upd)
            except Exception:
                pass

        def _finish(ok=True, msg=""):
            state["finished"] = True

            def upd():
                try:
                    pbar.configure(value=100 if ok else 0)
                    pct_lbl.configure(text="100%" if ok else "")
                    if ok:
                        status_lbl.configure(
                            text=msg or "✅ Завершено успешно", fg=c["GREEN"])
                    else:
                        status_lbl.configure(
                            text=msg or "⚠ Завершено с ошибкой", fg=c["RED"])
                    for w in close_holder.winfo_children():
                        w.destroy()
                    RoundedButton(close_holder, "Готово", dlg.destroy,
                                  bg=c["GREEN"], fg=c["ON_ACCENT"],
                                  hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.2),
                                  hover_fg=c["ON_ACCENT"],
                                  width=140, height=40,
                                  canvas_bg=c["BG"]).pack(side="right")
                except Exception:
                    pass
            try:
                self.root.after(0, upd)
            except Exception:
                pass

        def _on_close():
            if not state["finished"]:
                if not messagebox.askyesno(
                        title,
                        "Процесс ещё выполняется.\n\n"
                        "Свернуть окно? Операция продолжится в фоне, "
                        "а результат появится в главном логе.",
                        parent=dlg):
                    return
            state["cancelled"] = True
            try:
                dlg.destroy()
            except Exception:
                pass

        dlg.protocol("WM_DELETE_WINDOW", _on_close)

        RoundedButton(close_holder, "Свернуть", _on_close,
                      bg=c["CARD_2"], fg=c["FG"],
                      hover_bg=c["BORDER"], hover_fg=c["FG_DIM"],
                      width=140, height=40,
                      canvas_bg=c["BG"]).pack(side="right")

        state["log"] = _log
        state["set_status"] = _set_status
        state["set_progress"] = _set_progress
        state["finish"] = _finish
        state["widget"] = dlg
        return state

    def _repair_unlock_windows(self):
        ru = self.lang == "ru"
        if not is_admin():
            messagebox.showerror(
                self.T["err_title"],
                "Запусти SentryX от имени администратора." if ru
                else "Run SentryX as administrator.")
            return
        prompt = (
            "Будут восстановлены стандартные Shell/Userinit, удалены известные блокировки Windows, "
            "включены отключённые устройства клавиатуры/мыши и проверены системные файлы. "
            "Исходные значения реестра сохранятся в Backups. Некоторые изменения вступят в силу после перезагрузки. Продолжить?"
            if ru else
            "This restores the standard Shell/Userinit values, removes common Windows restrictions, "
            "enables disabled keyboard/mouse devices, and checks protected system files. Original "
            "registry values are saved under Backups. Some changes require a restart. Continue?")
        if not messagebox.askyesno("Разблокировка Windows" if ru else "Windows access recovery",
                                   prompt, parent=self.root):
            return

        self._repair_log("═" * 60, "dim")
        self._repair_log("🔓 Восстановление доступа Windows..." if ru
                         else "🔓 Recovering Windows access...", "info")
        self._repair_set_status("Восстановление..." if ru else "Recovering...",
                                self.C["ACCENT"])
        try:
            user32 = ctypes.windll.user32
            user32.SystemParametersInfoW(0x0057, 0, None, 0x0002)
            # ShowCursor uses a display counter; bring it back to the visible range.
            for _ in range(20):
                if user32.ShowCursor(True) >= 0:
                    break
            self._repair_log("Курсор: стандартная схема загружена." if ru
                             else "Cursor: standard scheme reloaded.", "ok")
        except Exception as e:
            self._repair_log(f"Курсор: {e}", "warn")

        def worker():
            backup_path, changed, errors = recover_windows_access_settings()
            if backup_path:
                self.root.after(0, self._repair_log,
                                f"Резервная копия: {backup_path}" if ru
                                else f"Registry backup: {backup_path}", "dim")
                self.root.after(0, self._repair_log,
                                (f"Изменено/удалено значений реестра: {changed}" if ru
                                 else f"Registry values repaired/removed: {changed}"), "ok")
            else:
                errors += 1
                self.root.after(0, self._repair_log,
                                "Не удалось сохранить резервную копию реестра; изменения реестра не внесены." if ru
                                else "Could not save the registry backup; registry was not changed.", "err")

            pnp_script = (
                "$ErrorActionPreference='Continue'; "
                "$d=Get-PnpDevice -Class Keyboard,Mouse -ErrorAction SilentlyContinue | "
                "Where-Object { $_.Status -eq 'Disabled' }; "
                "foreach($x in $d){try { Enable-PnpDevice -InstanceId $x.InstanceId "
                "-Confirm:$false -ErrorAction Stop; 'ENABLED: ' + $x.FriendlyName } "
                "catch { 'FAILED: ' + $x.FriendlyName + ' - ' + $_.Exception.Message }}; "
                "if(-not $d){'No disabled keyboard/mouse devices found.'}"
            )
            rc, out, err = _run_hidden(
                ["powershell", "-NoProfile", "-Command", pnp_script],
                timeout=90, encoding="utf-8")
            for line in (out or err or "").splitlines():
                self.root.after(0, self._repair_log, line, "ok" if line.startswith("ENABLED:") else "dim")
            if rc != 0:
                errors += 1
                self.root.after(0, self._repair_log,
                                f"PnP exit code: {rc}", "warn")

            system32 = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")
            for filename in ("sethc.exe", "utilman.exe", "userinit.exe"):
                target = os.path.join(system32, filename)
                self.root.after(0, self._repair_log,
                                f"SFC: {filename}...", "info")
                rc, out, err = _run_hidden(
                    ["sfc", f"/scanfile={target}"], timeout=240, encoding="cp866")
                details = (out or err or "").strip().splitlines()
                result = details[-1] if details else f"SFC exit code: {rc}"
                self.root.after(0, self._repair_log, result,
                                "ok" if rc == 0 else "warn")
                if rc != 0:
                    errors += 1

            self.root.after(0, self._repair_log, "─" * 60, "dim")
            self.root.after(0, self._repair_log,
                            "Готово. Перезагрузи Windows, чтобы применить изменения входа и устройств." if ru
                            else "Done. Restart Windows to apply logon and device changes.",
                            "ok" if errors == 0 else "warn")
            self.root.after(0, self._repair_set_status,
                            "Готово" if ru else "Finished",
                            self.C["GREEN"] if errors == 0 else self.C["YELLOW"])

        threading.Thread(target=worker, daemon=True).start()

    def _repair_run_sfc(self):
        ru = (self.lang == "ru")
        if not is_admin():
            messagebox.showerror(self.T["err_title"],
                                 "❌ Нужны права администратора." if ru
                                 else "❌ Administrator rights required.")
            self._repair_log(("❌ Нужны права администратора." if ru
                              else "❌ Administrator rights required."), "err")
            return

        cur = getattr(self, "_progress_dialogs", {})
        if cur.get("sfc") is not None:
            try:
                cur["sfc"]["widget"].lift()
                cur["sfc"]["widget"].focus_force()
                return
            except Exception:
                pass

        title = "🔧 SFC — Проверка системных файлов" if ru else "🔧 SFC — System File Checker"
        sub = ("⏱ Это может занять 5–15 минут" if ru
               else "⏱ This may take 5–15 minutes")
        pd = self._open_progress_dialog(title, sub, icon="🔧")
        if not hasattr(self, "_progress_dialogs"):
            self._progress_dialogs = {}
        self._progress_dialogs["sfc"] = pd

        pd["log"]("═" * 60, "dim")
        pd["log"]("🔧 SFC /scannow — " + ("запуск..." if ru else "starting..."), "bold")
        pd["log"](("⏱ Это может занять 5–15 минут." if ru
                   else "⏱ This may take 5–15 minutes."), "warn")
        pd["set_status"]("SFC запускается...", self.C["ACCENT"])
        pd["set_progress"](0)

        self._repair_log("═" * 60, "dim")
        self._repair_log("🔧 SFC /scannow — " + ("запуск..." if ru
                                                  else "starting..."), "bold")
        self._repair_set_status("SFC running...", self.C["ACCENT"])

        def on_line(line):
            if not line.strip():
                return
            tag = "info"
            low = line.lower()
            if "не обнаруж" in low or "no integrity" in low or "успешно" in low \
               or "successfully" in low:
                tag = "ok"
            elif "нарушен" in low or "corrupt" in low or "не удалось" in low \
                 or "failed" in low:
                tag = "warn"
            elif "восстанов" in low or "repaired" in low:
                tag = "ok"
            pd["log"]("  " + line, tag)
            self._repair_log("  " + line, tag)

        def on_done(rc):
            if rc == 0:
                pd["log"]("─" * 60, "dim")
                pd["log"]("✅ SFC завершён.", "ok")
                pd["finish"](True, "✅ SFC завершён успешно")
                self._repair_log("─" * 60, "dim")
                self._repair_log("✅ SFC завершён.", "ok")
                self._repair_set_status("SFC done", self.C["GREEN"])
            else:
                pd["log"]("─" * 60, "dim")
                pd["log"](f"⚠ SFC завершён с кодом {rc}", "warn")
                pd["finish"](False, f"⚠ SFC завершён с кодом {rc}")
                self._repair_log("─" * 60, "dim")
                self._repair_log(f"⚠ SFC завершён с кодом {rc}", "warn")
                self._repair_set_status(f"SFC exit {rc}", self.C["YELLOW"])
            try:
                self._progress_dialogs["sfc"] = None
            except Exception:
                pass

        def on_progress(pct):
            pd["set_progress"](pct)
            pd["set_status"](f"SFC: {pct}%", self.C["ACCENT"])
            self._repair_set_status(f"SFC: {pct}%", self.C["ACCENT"])

        run_streaming(["sfc", "/scannow"], on_line, on_done,
                      on_progress=on_progress)

    def _repair_run_dism(self):
        ru = (self.lang == "ru")
        if not is_admin():
            messagebox.showerror(self.T["err_title"],
                                 "❌ Нужны права администратора." if ru
                                 else "❌ Administrator rights required.")
            self._repair_log(("❌ Нужны права администратора." if ru
                              else "❌ Administrator rights required."), "err")
            return

        cur = getattr(self, "_progress_dialogs", {})
        if cur.get("dism") is not None:
            try:
                cur["dism"]["widget"].lift()
                cur["dism"]["widget"].focus_force()
                return
            except Exception:
                pass

        title = ("🛠 DISM — Восстановление образа" if ru
                 else "🛠 DISM — Image Restore")
        sub = ("⏱ 10–30 минут. Требуется интернет" if ru
               else "⏱ 10–30 min. Internet required")
        pd = self._open_progress_dialog(title, sub, icon="🛠")
        if not hasattr(self, "_progress_dialogs"):
            self._progress_dialogs = {}
        self._progress_dialogs["dism"] = pd

        pd["log"]("═" * 60, "dim")
        pd["log"]("🛠 DISM RestoreHealth — " + ("запуск..." if ru
                                                 else "starting..."), "bold")
        pd["log"](("⏱ Это может занять 10–30 минут. Нужен интернет." if ru
                   else "⏱ 10–30 min. Internet required."), "warn")
        pd["set_status"]("DISM запускается...", self.C["ACCENT_2"])
        pd["set_progress"](0)

        self._repair_log("═" * 60, "dim")
        self._repair_log("🛠 DISM RestoreHealth — " + ("запуск..." if ru
                                                        else "starting..."), "bold")
        self._repair_set_status("DISM running...", self.C["ACCENT_2"])

        def on_line(line):
            if not line.strip():
                return
            tag = "info"
            low = line.lower()
            if "восстановление" in low and "успешно" in low:
                tag = "ok"
            elif "restore" in low and ("completed" in low or "successfully" in low):
                tag = "ok"
            elif "ошибка" in low or "error" in low:
                tag = "err"
            elif "процент" in low or "%" in low:
                tag = "warn"
            pd["log"]("  " + line, tag)
            self._repair_log("  " + line, tag)

        def on_done(rc):
            if rc == 0:
                pd["log"]("─" * 60, "dim")
                pd["log"]("✅ DISM завершён.", "ok")
                pd["finish"](True, "✅ DISM завершён успешно")
                self._repair_log("─" * 60, "dim")
                self._repair_log("✅ DISM завершён.", "ok")
                self._repair_set_status("DISM done", self.C["GREEN"])
            else:
                pd["log"]("─" * 60, "dim")
                pd["log"](f"⚠ DISM завершён с кодом {rc}", "warn")
                pd["finish"](False, f"⚠ DISM завершён с кодом {rc}")
                self._repair_log("─" * 60, "dim")
                self._repair_log(f"⚠ DISM завершён с кодом {rc}", "warn")
                self._repair_set_status(f"DISM exit {rc}", self.C["YELLOW"])
            try:
                self._progress_dialogs["dism"] = None
            except Exception:
                pass

        def on_progress(pct):
            pd["set_progress"](pct)
            pd["set_status"](f"DISM: {pct}%", self.C["ACCENT_2"])
            self._repair_set_status(f"DISM: {pct}%", self.C["ACCENT_2"])

        run_streaming(["DISM", "/Online", "/Cleanup-Image", "/RestoreHealth"],
                      on_line, on_done, on_progress=on_progress)

    def _repair_create_point(self):
        ru = (self.lang == "ru")
        self._repair_log("═" * 60, "dim")
        self._repair_log("💾 " + ("Создаю точку восстановления..." if ru
                                  else "Creating restore point..."), "bold")
        self._repair_set_status("Creating restore point...", self.C["GREEN"])

        def worker():
            ok, info = create_restore_point("SentryX")

            def finish():
                if ok:
                    self._repair_log(("✅ Точка восстановления создана." if ru
                                      else "✅ Restore point created."), "ok")
                    self._repair_set_status("Point created", self.C["GREEN"])
                else:
                    self._repair_log(("⚠ Не удалось. Возможно, защита системы выключена "
                                      "или нет прав администратора." if ru
                                      else "⚠ Failed. System protection may be off."),
                                     "warn")
                    if info:
                        self._repair_log("  " + info.strip()[:300], "dim")
                    self._repair_set_status("Failed", self.C["YELLOW"])
            self.root.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _repair_open_rstrui(self):
        try:
            subprocess.Popen(["rstrui.exe"], creationflags=CREATE_NO_WINDOW)
            self._repair_log(("→ Открыто окно восстановления системы." if self.lang == "ru"
                              else "→ System Restore window opened."), "info")
        except Exception as e:
            self._repair_log(f"[error] {e}", "err")

    def _repair_list_points(self):
        ru = (self.lang == "ru")
        self._repair_log("═" * 60, "dim")
        self._repair_log("📋 " + ("Получаю список точек..." if ru
                                  else "Fetching restore points..."), "bold")

        def worker():
            pts = list_restore_points()

            def finish():
                if not pts:
                    self._repair_log(("Точек восстановления нет." if ru
                                      else "No restore points."), "warn")
                    return
                self._repair_log(f"  {'SEQUENCE':<10} {'DATE':<22} DESCRIPTION", "dim")
                for p in pts:
                    self._repair_log(f"  {p['seq']:<10} {p['date']:<22} {p['desc']}", "info")
            self.root.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _repair_backup_autorun(self):
        ru = (self.lang == "ru")
        self._repair_log("═" * 60, "dim")
        self._repair_log("📤 " + ("Делаю бэкап автозагрузки..." if ru
                                  else "Backing up autorun..."), "bold")
        fp = backup_autorun()
        if fp:
            self._repair_log(("✅ Бэкап сохранён: " if ru else "✅ Backup saved: ") + fp, "ok")
            self._repair_log(("💡 Теперь можешь восстановить одним кликом." if ru
                              else "💡 You can restore with one click."), "dim")
            self._repair_set_status("Backup OK", self.C["GREEN"])
        else:
            self._repair_log(("❌ Не удалось создать бэкап." if ru
                              else "❌ Backup failed."), "err")
            self._repair_set_status("Backup failed", self.C["RED"])

    def _repair_restore_autorun(self):
        ru = (self.lang == "ru")
        if not messagebox.askyesno(
            "SentryX",
            ("Восстановить автозагрузку из последнего бэкапа?\n"
             "Текущие записи Run/RunOnce будут перезаписаны." if ru else
             "Restore autorun from last backup?\n"
             "Current Run/RunOnce entries will be overwritten.")):
            return
        self._repair_log("═" * 60, "dim")
        self._repair_log("📥 " + ("Восстанавливаю автозагрузку..." if ru
                                  else "Restoring autorun..."), "bold")
        restored, errors = restore_autorun()
        if restored > 0:
            self._repair_log((f"✅ Восстановлено значений: {restored}" if ru
                              else f"✅ Restored values: {restored}"), "ok")
            if errors:
                self._repair_log((f"⚠ Ошибок: {errors}" if ru
                                  else f"⚠ Errors: {errors}"), "warn")
            self._repair_set_status("Autorun restored", self.C["GREEN"])
        else:
            self._repair_log(("❌ Не удалось восстановить. "
                              "Возможно, бэкапа нет или нужны права админа." if ru
                              else "❌ Restore failed. No backup or admin required."),
                             "err")
            self._repair_set_status("Restore failed", self.C["RED"])

    # ---------- SETTINGS ----------
    def _page_settings(self):
        c = self.C
        page = tk.Frame(self.content_wrap, bg=c["BG"])
        canvas = tk.Canvas(page, bg=c["BG"], highlightthickness=0)
        scroll = ttk.Scrollbar(page, orient="vertical",
                               style="Dark.Vertical.TScrollbar", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        wrap = tk.Frame(canvas, bg=c["BG"])
        win = canvas.create_window((0, 0), window=wrap, anchor="nw")

        def on_conf(e):
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
                canvas.itemconfigure(win, width=canvas.winfo_width())
            except Exception:
                pass
        wrap.bind("<Configure>", on_conf)
        canvas.bind("<Configure>", on_conf)

        def _mw(event):
            try:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except Exception:
                pass

        def _bind_wheel(widget):
            try:
                widget.bind("<MouseWheel>", _mw, add="+")
                for ch in widget.winfo_children():
                    _bind_wheel(ch)
            except Exception:
                pass
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _mw))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        inner = tk.Frame(wrap, bg=c["BG"])
        inner.pack(fill="both", expand=True, padx=25, pady=20)
        h = tk.Frame(inner, bg=c["BG"])
        h.pack(fill="x", pady=(0, 14))
        tk.Label(h, text=self.T["set_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(h, text=self.T["set_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

        card = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                        highlightbackground=c["BORDER"])
        card.pack(fill="x", pady=(0, 12))
        i = tk.Frame(card, bg=c["CARD"])
        i.pack(fill="x", padx=20, pady=16)
        tk.Label(i, text=self.T["set_appear"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 12))
        tr = tk.Frame(i, bg=c["CARD"])
        tr.pack(fill="x", pady=(0, 12))
        tk.Label(tr, text=self.T["set_theme"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(side="left")
        tb = tk.Frame(tr, bg=c["CARD"])
        tb.pack(side="right")
        RoundedButton(tb, self.T["set_theme_dark"], lambda: self.set_theme("dark"),
                      bg=c["CARD_2"] if self.theme != "dark" else c["ACCENT"],
                      fg=c["FG"] if self.theme != "dark" else c["ON_ACCENT"],
                      hover_bg=c["BORDER"] if self.theme != "dark" else c["ACCENT"],
                      hover_fg=c["ACCENT"] if self.theme != "dark" else c["ON_ACCENT"],
                      width=140, height=40, canvas_bg=c["CARD"]
                      ).pack(side="left", padx=(0, 8))
        RoundedButton(tb, self.T["set_theme_light"], lambda: self.set_theme("light"),
                      bg=c["CARD_2"] if self.theme != "light" else c["ACCENT"],
                      fg=c["FG"] if self.theme != "light" else c["ON_ACCENT"],
                      hover_bg=c["BORDER"] if self.theme != "light" else c["ACCENT"],
                      hover_fg=c["ACCENT"] if self.theme != "light" else c["ON_ACCENT"],
                      width=140, height=40, canvas_bg=c["CARD"]).pack(side="left")
        lr = tk.Frame(i, bg=c["CARD"])
        lr.pack(fill="x")
        tk.Label(lr, text=self.T["set_lang"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(side="left")
        lb = tk.Frame(lr, bg=c["CARD"])
        lb.pack(side="right")
        RoundedButton(lb, self.T["set_lang_ru"], lambda: self.set_lang("ru"),
                      bg=c["CARD_2"] if self.lang != "ru" else c["ACCENT"],
                      fg=c["FG"] if self.lang != "ru" else c["ON_ACCENT"],
                      hover_bg=c["BORDER"] if self.lang != "ru" else c["ACCENT"],
                      hover_fg=c["ACCENT"] if self.lang != "ru" else c["ON_ACCENT"],
                      width=140, height=40, canvas_bg=c["CARD"]
                      ).pack(side="left", padx=(0, 8))
        RoundedButton(lb, self.T["set_lang_en"], lambda: self.set_lang("en"),
                      bg=c["CARD_2"] if self.lang != "en" else c["ACCENT"],
                      fg=c["FG"] if self.lang != "en" else c["ON_ACCENT"],
                      hover_bg=c["BORDER"] if self.lang != "en" else c["ACCENT"],
                      hover_fg=c["ACCENT"] if self.lang != "en" else c["ON_ACCENT"],
                      width=140, height=40, canvas_bg=c["CARD"]).pack(side="left")

        scene_card = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                              highlightbackground=c["BORDER"])
        scene_card.pack(fill="x", pady=(0, 12))
        sci = tk.Frame(scene_card, bg=c["CARD"])
        sci.pack(fill="x", padx=20, pady=16)
        ru = self.lang == "ru"
        tk.Label(sci, text="\u0422\u0415\u041c\u042b \u0418 \u041e\u0411\u041e\u0418" if ru else "THEMES & WALLPAPERS",
                 bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(sci,
                 text="\u0412\u044b\u0431\u0435\u0440\u0438 \u0442\u0435\u043c\u0443, \u043e\u0431\u043e\u0438 \u0438 \u044d\u0444\u0444\u0435\u043a\u0442. \u041d\u0430 \u0433\u043b\u0430\u0432\u043d\u043e\u0439 \u043f\u0435\u0440\u0435\u0442\u0430\u0441\u043a\u0438\u0432\u0430\u0439 \u0444\u043e\u0442\u043e, \u0447\u0442\u043e\u0431\u044b \u0432\u044b\u0431\u0440\u0430\u0442\u044c \u043d\u0443\u0436\u043d\u0443\u044e \u0447\u0430\u0441\u0442\u044c \u043a\u0430\u0434\u0440\u0430" if ru else "Choose a theme, wallpaper and effect. Drag the image on Home to frame the part you want",
                 bg=c["CARD"], fg=c["FG_DIM"], wraplength=760,
                 justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 12))
        scene_row = tk.Frame(sci, bg=c["CARD"])
        scene_row.pack(fill="x", pady=(0, 12))
        scene_labels = {
            "aurora": "\u0421\u0438\u044f\u043d\u0438\u0435" if ru else "Aurora",
            "ocean": "\u041e\u043a\u0435\u0430\u043d" if ru else "Ocean",
            "forest": "\u041b\u0435\u0441" if ru else "Forest",
            "ember": "\u0417\u0430\u043a\u0430\u0442" if ru else "Ember",
            "arctic": "\u0410\u0440\u043a\u0442\u0438\u043a\u0430" if ru else "Arctic",
        }
        for scene_key, scene_label in scene_labels.items():
            active = self.visual_scene == scene_key
            RoundedButton(scene_row, scene_label,
                          lambda key=scene_key: self.set_visual_scene(key),
                          bg=c["ACCENT"] if active else c["CARD_2"],
                          fg=c["ON_ACCENT"] if active else c["FG"],
                          hover_bg=c["ACCENT"] if active else c["BORDER"],
                          hover_fg=c["ON_ACCENT"] if active else c["FG"],
                          width=118, height=38, canvas_bg=c["CARD"]
                          ).pack(side="left", padx=(0, 7))

        effect_row = tk.Frame(sci, bg=c["CARD"])
        effect_row.pack(fill="x", pady=(0, 12))
        tk.Label(effect_row,
                 text="\u042d\u0444\u0444\u0435\u043a\u0442" if ru else "Effect",
                 bg=c["CARD"], fg=c["FG"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 12))
        for effect_key, effect_label in (("off", "\u041d\u0435\u0442" if ru else "Off"),
                                         ("snow", "\u0421\u043d\u0435\u0433" if ru else "Snow"),
                                         ("rain", "\u0414\u043e\u0436\u0434\u044c" if ru else "Rain")):
            active = self.scene_effect == effect_key
            RoundedButton(effect_row, effect_label,
                          lambda key=effect_key: self.set_scene_effect(key),
                          bg=c["ACCENT"] if active else c["CARD_2"],
                          fg=c["ON_ACCENT"] if active else c["FG"],
                          hover_bg=c["ACCENT"] if active else c["BORDER"],
                          hover_fg=c["ON_ACCENT"] if active else c["FG"],
                          width=105, height=36, canvas_bg=c["CARD"]
                          ).pack(side="left", padx=(0, 7))

        wallpaper_row = tk.Frame(sci, bg=c["CARD"])
        wallpaper_row.pack(fill="x")
        current_wallpaper = os.path.basename(self.wallpaper_path) if self.wallpaper_path else (
            "\u041d\u0435 \u0432\u044b\u0431\u0440\u0430\u043d\u044b" if ru else "No wallpaper selected")
        tk.Label(wallpaper_row, text=current_wallpaper, bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
        RoundedButton(wallpaper_row,
                      "\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044c" if ru else "Choose image",
                      self.choose_wallpaper, bg=c["CARD_2"], fg=c["FG"],
                      hover_bg=c["BORDER"], hover_fg=c["FG"], width=130,
                      height=38, canvas_bg=c["CARD"]).pack(side="left", padx=(8, 0))
        if self.wallpaper_path:
            RoundedButton(wallpaper_row,
                          "\u0421\u0431\u0440\u043e\u0441" if ru else "Clear",
                          self.clear_wallpaper, bg=c["CARD_2"], fg=c["FG"],
                          hover_bg=c["BORDER"], hover_fg=c["FG"], width=90,
                          height=38, canvas_bg=c["CARD"]).pack(side="left", padx=(8, 0))

        asc = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                       highlightbackground=c["BORDER"])
        asc.pack(fill="x", pady=(0, 12))
        asi = tk.Frame(asc, bg=c["CARD"])
        asi.pack(fill="x", padx=20, pady=16)
        tk.Label(asi, text="🚀  " + self.T["set_autostart"].upper(),
                 bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 12))
        asr = tk.Frame(asi, bg=c["CARD"])
        asr.pack(fill="x")
        asinfo = tk.Frame(asr, bg=c["CARD"])
        asinfo.pack(side="left")
        tk.Label(asinfo, text=self.T["set_autostart"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        ashint = self.T["set_autostart_hint"]
        ashcol = c["FG_DIM"]
        if not HAS_WINREG:
            ashint = self.T["set_autostart_unavailable"]
            ashcol = c["YELLOW"]
        tk.Label(asinfo, text=ashint, bg=c["CARD"], fg=ashcol,
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        asb = tk.Frame(asr, bg=c["CARD"])
        asb.pack(side="right")
        as_on = is_autostart_installed() and HAS_WINREG
        as_btn = RoundedButton(asb, self.T["btn_on"] if as_on else self.T["btn_off"],
                               self._toggle_autostart,
                               bg=c["GREEN"] if as_on else c["CARD_2"],
                               fg=c["ON_ACCENT"] if as_on else c["FG_DIM"],
                               hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.25) if as_on else c["BORDER"],
                               hover_fg=c["ON_ACCENT"] if as_on else c["ACCENT"],
                               width=110, height=40, canvas_bg=c["CARD"])
        as_btn.pack(side="left")
        if not HAS_WINREG:
            as_btn.set_enabled(False)

        acc_card = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                            highlightbackground=c["BORDER"])
        acc_card.pack(fill="x", pady=(0, 12))
        ai = tk.Frame(acc_card, bg=c["CARD"])
        ai.pack(fill="x", padx=20, pady=16)
        tk.Label(ai, text=self.T["set_account"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 12))
        ar = tk.Frame(ai, bg=c["CARD"])
        ar.pack(fill="x")
        ainfo = tk.Frame(ar, bg=c["CARD"])
        ainfo.pack(side="left")
        if self.current_user:
            tk.Label(ainfo, text=self.T["set_acc_logged"].format(name=self.current_user),
                     bg=c["CARD"], fg=c["FG"],
                     font=("Segoe UI", 11, "bold")).pack(anchor="w")
            tk.Label(ainfo, text=self.T["set_acc_logged_hint"],
                     bg=c["CARD"], fg=c["FG_DIM"], font=("Segoe UI", 8),
                     wraplength=500, justify="left").pack(anchor="w", pady=(2, 0))
        else:
            tk.Label(ainfo, text=self.T["set_acc_guest"], bg=c["CARD"], fg=c["FG"],
                     font=("Segoe UI", 11, "bold")).pack(anchor="w")
            tk.Label(ainfo, text=self.T["set_acc_guest_hint"],
                     bg=c["CARD"], fg=c["FG_DIM"], font=("Segoe UI", 8),
                     wraplength=500, justify="left").pack(anchor="w", pady=(2, 0))
        ab = tk.Frame(ar, bg=c["CARD"])
        ab.pack(side="right")
        if self.current_user:
            RoundedButton(ab, self.T["set_acc_logout"], self._action_logout,
                          bg=c["CARD_2"], fg=c["FG"],
                          hover_bg=c["BORDER"], hover_fg=c["RED"],
                          width=180, height=40, canvas_bg=c["CARD"]
                          ).pack(side="left", padx=(0, 8))
            RoundedButton(ab, self.T["set_acc_manage"], self._open_account_manager,
                          bg=c["ACCENT"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=200, height=40,
                          canvas_bg=c["CARD"]).pack(side="left")
        else:
            RoundedButton(ab, self.T["set_acc_manage"], self._open_account_manager,
                          bg=c["ACCENT"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=220, height=40,
                          canvas_bg=c["CARD"]).pack(side="left")

        pc = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        pc.pack(fill="x", pady=(0, 12))
        pi = tk.Frame(pc, bg=c["CARD"])
        pi.pack(fill="x", padx=20, pady=16)
        tk.Label(pi, text=self.T["set_protection"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 12))

        rt_row = tk.Frame(pi, bg=c["CARD"])
        rt_row.pack(fill="x", pady=(0, 12))
        rti = tk.Frame(rt_row, bg=c["CARD"])
        rti.pack(side="left")
        tk.Label(rti, text=self.T["set_realtime"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        tk.Label(rti, text=self.T["set_realtime_hint"], bg=c["CARD"],
                 fg=c["FG_DIM"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        rtb = tk.Frame(rt_row, bg=c["CARD"])
        rtb.pack(side="right")
        rt_on = self.realtime_protection
        RoundedButton(rtb, self.T["btn_on"] if rt_on else self.T["btn_off"],
                      self._toggle_realtime_protection,
                      bg=c["GREEN"] if rt_on else c["CARD_2"],
                      fg=c["ON_ACCENT"] if rt_on else c["FG_DIM"],
                      hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.25) if rt_on else c["BORDER"],
                      hover_fg=c["ON_ACCENT"] if rt_on else c["ACCENT"],
                      width=110, height=40, canvas_bg=c["CARD"]).pack(side="left")

        adr = tk.Frame(pi, bg=c["CARD"])
        adr.pack(fill="x", pady=(0, 12))
        adi = tk.Frame(adr, bg=c["CARD"])
        adi.pack(side="left")
        tk.Label(adi, text=self.T["set_auto_downloads"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        wh = self.T["set_auto_downloads_hint"]
        wc = c["FG_DIM"]
        if not HAS_WATCHDOG:
            wh = self.T["watchdog_missing"]
            wc = c["YELLOW"]
        tk.Label(adi, text=wh, bg=c["CARD"], fg=wc,
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        adb = tk.Frame(adr, bg=c["CARD"])
        adb.pack(side="right")
        aon = self.auto_downloads and HAS_WATCHDOG
        abtn = RoundedButton(adb, self.T["btn_on"] if aon else self.T["btn_off"],
                             self._toggle_auto_downloads,
                             bg=c["GREEN"] if aon else c["CARD_2"],
                             fg=c["ON_ACCENT"] if aon else c["FG_DIM"],
                             hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.25) if aon else c["BORDER"],
                             hover_fg=c["ON_ACCENT"] if aon else c["ACCENT"],
                             width=110, height=40, canvas_bg=c["CARD"])
        abtn.pack(side="left")
        if not HAS_WATCHDOG:
            abtn.set_enabled(False)
        nr = tk.Frame(pi, bg=c["CARD"])
        nr.pack(fill="x")
        ni = tk.Frame(nr, bg=c["CARD"])
        ni.pack(side="left")
        tk.Label(ni, text=self.T["set_notifications"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        tk.Label(ni, text=self.T["set_notifications_hint"], bg=c["CARD"],
                 fg=c["FG_DIM"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        nb = tk.Frame(nr, bg=c["CARD"])
        nb.pack(side="right")
        non = self.notifications_enabled
        RoundedButton(nb, self.T["btn_on"] if non else self.T["btn_off"],
                      self._toggle_notifications,
                      bg=c["GREEN"] if non else c["CARD_2"],
                      fg=c["ON_ACCENT"] if non else c["FG_DIM"],
                      hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.25) if non else c["BORDER"],
                      hover_fg=c["ON_ACCENT"] if non else c["ACCENT"],
                      width=110, height=40, canvas_bg=c["CARD"]).pack(side="left")

        ic = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        ic.pack(fill="x", pady=(0, 12))
        ii = tk.Frame(ic, bg=c["CARD"])
        ii.pack(fill="x", padx=20, pady=16)
        tk.Label(ii, text=self.T["set_integration"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 10))
        self._build_ctx_block(ii)

        dc2 = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                       highlightbackground=c["BORDER"])
        dc2.pack(fill="x", pady=(0, 12))
        di = tk.Frame(dc2, bg=c["CARD"])
        di.pack(fill="x", padx=20, pady=16)
        tk.Label(di, text=self.T["set_data"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 10))
        bd = tk.Frame(di, bg=c["CARD"])
        bd.pack(anchor="w")
        RoundedButton(bd, self.T["set_open_quar"], self._open_quarantine_folder,
                      bg=c["CARD_2"], fg=c["FG"], hover_bg=c["BORDER"],
                      hover_fg=c["ACCENT"], width=220, height=42,
                      canvas_bg=c["CARD"]).pack(side="left", padx=(0, 8))
        RoundedButton(bd, self.T["set_open_logs"], self._open_data_folder,
                      bg=c["CARD_2"], fg=c["FG"], hover_bg=c["BORDER"],
                      hover_fg=c["ACCENT"], width=220, height=42,
                      canvas_bg=c["CARD"]).pack(side="left", padx=(0, 8))
        RoundedButton(bd, self.T["set_clear_hist"], self._clear_history,
                      bg=c["CARD_2"], fg=c["RED"], hover_bg=c["BORDER"],
                      hover_fg=c["RED"], width=220, height=42,
                      canvas_bg=c["CARD"]).pack(side="left")

        uc = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        uc.pack(fill="x", pady=(0, 12))
        ui = tk.Frame(uc, bg=c["CARD"])
        ui.pack(fill="x", padx=20, pady=16)
        tk.Label(ui, text=self.T["upd_section"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 12))

        ur = tk.Frame(ui, bg=c["CARD"])
        ur.pack(fill="x")
        uinfo = tk.Frame(ur, bg=c["CARD"])
        uinfo.pack(side="left", fill="x", expand=True)
        tk.Label(uinfo, text=self.T["upd_auto_check"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        tk.Label(uinfo, text=self.T["upd_auto_check_hint"], bg=c["CARD"],
                 fg=c["FG_DIM"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        ubtn_wrap = tk.Frame(ur, bg=c["CARD"])
        ubtn_wrap.pack(side="right")

        def manual_check():
            self._check_for_updates(silent=False)

        RoundedButton(ui, self.T["upd_check_btn"], manual_check,
                      bg=c["ACCENT"], fg=c["ON_ACCENT"],
                      hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                      hover_fg=c["ON_ACCENT"], width=260, height=42,
                      canvas_bg=c["CARD"]).pack(anchor="w", pady=(12, 0))

        ustate = load_json(UPDATE_STATE_FILE, {})
        ulast = ustate.get("last_check") or self.T["upd_never_checked"]
        tk.Label(ui, text=self.T["upd_last_check"].format(t=ulast),
                 bg=c["CARD"], fg=c["FG_DIM"], font=("Cascadia Code", 8)
                 ).pack(anchor="w", pady=(8, 0))

        dc = tk.Frame(inner, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        dc.pack(fill="x", pady=(0, 12))
        dn = tk.Frame(dc, bg=c["CARD"])
        dn.pack(fill="x", padx=20, pady=16)
        tk.Label(dn, text=self.T["set_defender"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.settings_status = tk.Label(dn, text=self.T["set_def_loading"],
                                        bg=c["CARD"], fg=c["FG"],
                                        font=("Cascadia Code", 10), justify="left")
        self.settings_status.pack(anchor="w", pady=(10, 0))
        b2 = tk.Frame(inner, bg=c["BG"])
        b2.pack(fill="x")
        RoundedButton(b2, self.T["btn_refresh"], self.refresh_settings,
                      bg=c["ACCENT"], fg=c["ON_ACCENT"],
                      hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                      hover_fg=c["ON_ACCENT"], width=220, height=44,
                      canvas_bg=c["BG"]).pack(side="left")
        RoundedButton(b2, self.T["btn_update_sigs"], self.update_signatures,
                      bg=c["ACCENT_2"], fg=c["ON_ACCENT"],
                      hover_bg=lerp_color(c["ACCENT_2"], "#ffffff", 0.25),
                      hover_fg=c["ON_ACCENT"], width=220, height=44,
                      canvas_bg=c["BG"]).pack(side="left", padx=(12, 0))
        self.root.after(200, self.refresh_settings)
        self.root.after(100, lambda: _bind_wheel(inner))
        return page

    def _build_ctx_block(self, parent):
        c = self.C
        if self._ctx_render is not None:
            try:
                if self._ctx_render.winfo_exists():
                    self._ctx_render.destroy()
            except Exception:
                pass
        h = tk.Frame(parent, bg=c["CARD"])
        h.pack(fill="x")
        self._ctx_render = h
        inst = is_ctx_installed()
        ci = tk.Frame(h, bg=c["CARD"])
        ci.pack(side="left")
        tk.Label(ci, text=self.T["set_ctx_menu"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        st = self.T["set_ctx_installed"] if inst else self.T["set_ctx_hint"]
        sc = c["GREEN"] if inst else c["FG_DIM"]
        tk.Label(ci, text=st, bg=c["CARD"], fg=sc, font=("Segoe UI", 8)
                 ).pack(anchor="w", pady=(2, 0))
        cb = tk.Frame(h, bg=c["CARD"])
        cb.pack(side="right")
        bi = RoundedButton(cb, self.T["set_ctx_install"], self._install_ctx,
                           bg=c["GREEN"], fg=c["ON_ACCENT"],
                           hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.25),
                           hover_fg=c["ON_ACCENT"], width=150, height=40,
                           canvas_bg=c["CARD"])
        bi.pack(side="left", padx=(0, 8))
        if inst:
            bi.set_enabled(False)
        br = RoundedButton(cb, self.T["set_ctx_remove"], self._uninstall_ctx,
                           bg=c["CARD_2"], fg=c["RED"],
                           hover_bg=c["BORDER"], hover_fg=c["RED"],
                           width=150, height=40, canvas_bg=c["CARD"])
        br.pack(side="left")
        if not inst:
            br.set_enabled(False)

    def _install_ctx(self):
        if install_context_menu():
            messagebox.showinfo(self.T["set_ctx_menu"],
                                "✅ Установлено" if self.lang == "ru" else "✅ Installed")
            self._refresh_ctx_block()
        else:
            messagebox.showerror(self.T["err_title"],
                                 "Ошибка установки" if self.lang == "ru"
                                 else "Installation error")

    def _uninstall_ctx(self):
        if uninstall_context_menu():
            messagebox.showinfo(self.T["set_ctx_menu"],
                                "✅ Удалено" if self.lang == "ru" else "✅ Removed")
            self._refresh_ctx_block()
        else:
            messagebox.showerror(self.T["err_title"],
                                 "Ошибка удаления" if self.lang == "ru"
                                 else "Removal error")

    def _refresh_ctx_block(self):
        try:
            if self._ctx_render is not None:
                parent = self._ctx_render.master
                self._build_ctx_block(parent)
        except Exception:
            self._rebuild_preserve()

    def _open_quarantine_folder(self):
        try:
            os.startfile(QUARANTINE_DIR)
        except Exception:
            pass

    def _open_data_folder(self):
        try:
            user = get_current_user()
            folder = os.path.join(ACCOUNTS_DIR, user) if user else GUEST_DIR
            os.startfile(folder)
        except Exception:
            pass

    def _clear_history(self):
        save_json(HISTORY_FILE, {"scans": []})
        messagebox.showinfo(self.T["set_title"], self.T["set_clear_hist_ok"])
        self._rebuild_preserve()

    def _open_account_manager(self):
        c = self.C
        dlg = tk.Toplevel(self.root)
        dlg.title(self.T["acc_title"])
        dlg.configure(bg=c["BG"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        w, h = 500, 520
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
        dlg.geometry(f"{w}x{h}+{x}+{y}")
        tk.Label(dlg, text=self.T["acc_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 16, "bold")).pack(pady=(18, 2))
        tk.Label(dlg, text=self.T["acc_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 9)).pack()

        if self.current_user:
            info = tk.Frame(dlg, bg=c["CARD"], highlightthickness=1,
                            highlightbackground=c["BORDER"])
            info.pack(fill="x", padx=30, pady=20)
            ii = tk.Frame(info, bg=c["CARD"])
            ii.pack(fill="x", padx=18, pady=18)
            tk.Label(ii, text="👤", bg=c["CARD"], fg=c["ACCENT"],
                     font=("Segoe UI Emoji", 28)).pack()
            tk.Label(ii, text=self.current_user, bg=c["CARD"], fg=c["FG"],
                     font=("Segoe UI", 14, "bold")).pack(pady=(4, 0))
            tk.Label(ii, text=self.T["acc_you"].format(name=""), bg=c["CARD"],
                     fg=c["FG_DIM"], font=("Segoe UI", 8)).pack()
            br = tk.Frame(dlg, bg=c["BG"])
            br.pack(pady=10)

            def do_logout():
                if messagebox.askyesno(self.T["acc_title"], self.T["acc_confirm_logout"]):
                    set_current_user("")
                    messagebox.showinfo(self.T["acc_title"], self.T["acc_logged_out"])
                    dlg.destroy()
                    self._restart_app()

            def do_delete():
                if messagebox.askyesno(self.T["acc_title"],
                                       self.T["acc_confirm_delete"].format(name=self.current_user)):
                    delete_account(self.current_user)
                    set_current_user("")
                    messagebox.showinfo(self.T["acc_title"], self.T["acc_deleted"])
                    dlg.destroy()
                    self._restart_app()

            RoundedButton(br, self.T["acc_btn_logout"], do_logout,
                          bg=c["ACCENT"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=180, height=44,
                          canvas_bg=c["BG"]).pack(side="left", padx=6)
            RoundedButton(br, self.T["acc_btn_delete"], do_delete,
                          bg=c["RED"], fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(c["RED"], "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=180, height=44,
                          canvas_bg=c["BG"]).pack(side="left", padx=6)
            RoundedButton(br, self.T["acc_btn_cancel"], dlg.destroy,
                          bg=c["CARD_2"], fg=c["FG"],
                          hover_bg=c["BORDER"], hover_fg=c["FG"],
                          width=120, height=44, canvas_bg=c["BG"]).pack(side="left", padx=6)
        else:
            mode_var = tk.StringVar(value="login")
            content = tk.Frame(dlg, bg=c["BG"])
            content.pack(fill="both", expand=True, padx=30, pady=(10, 10))

            def render_form():
                for w in content.winfo_children():
                    w.destroy()
                tabrow = tk.Frame(content, bg=c["BG"])
                tabrow.pack(fill="x")
                is_login = mode_var.get() == "login"
                RoundedButton(tabrow, self.T["acc_tab_login"],
                              lambda: (mode_var.set("login"), render_form()),
                              bg=c["ACCENT"] if is_login else c["CARD_2"],
                              fg=c["ON_ACCENT"] if is_login else c["FG"],
                              hover_bg=c["ACCENT"] if is_login else c["BORDER"],
                              hover_fg=c["ON_ACCENT"] if is_login else c["FG"],
                              width=200, height=40, canvas_bg=c["BG"]
                              ).pack(side="left", padx=(0, 10))
                RoundedButton(tabrow, self.T["acc_tab_register"],
                              lambda: (mode_var.set("register"), render_form()),
                              bg=c["CARD_2"] if is_login else c["ACCENT"],
                              fg=c["FG"] if is_login else c["ON_ACCENT"],
                              hover_bg=c["BORDER"] if is_login else c["ACCENT"],
                              hover_fg=c["FG"] if is_login else c["ON_ACCENT"],
                              width=200, height=40, canvas_bg=c["BG"]).pack(side="left")
                frm = tk.Frame(content, bg=c["BG"])
                frm.pack(fill="x", pady=(18, 0))
                tk.Label(frm, text=self.T["acc_name"], bg=c["BG"], fg=c["FG_DIM"],
                         font=("Segoe UI", 9, "bold")).pack(anchor="w")
                name_var = tk.StringVar()
                new = tk.Frame(frm, bg=c["INPUT"], highlightthickness=1,
                               highlightbackground=c["BORDER"])
                new.pack(fill="x", pady=(4, 12))
                en = tk.Entry(new, textvariable=name_var, bg=c["INPUT"], fg=c["FG"],
                              insertbackground=c["ACCENT"], relief="flat", bd=0,
                              font=("Cascadia Code", 11))
                en.pack(fill="x", padx=12, pady=10)
                tk.Label(frm, text=self.T["acc_password"], bg=c["BG"], fg=c["FG_DIM"],
                         font=("Segoe UI", 9, "bold")).pack(anchor="w")
                pw_var = tk.StringVar()
                new2 = tk.Frame(frm, bg=c["INPUT"], highlightthickness=1,
                                highlightbackground=c["BORDER"])
                new2.pack(fill="x", pady=(4, 12))
                ep = tk.Entry(new2, textvariable=pw_var, bg=c["INPUT"], fg=c["FG"],
                              insertbackground=c["ACCENT"], relief="flat", bd=0,
                              font=("Cascadia Code", 11), show="●")
                ep.pack(fill="x", padx=12, pady=10)
                pw2_var = tk.StringVar()
                if mode_var.get() == "register":
                    tk.Label(frm, text=self.T["acc_password2"], bg=c["BG"],
                             fg=c["FG_DIM"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
                    new3 = tk.Frame(frm, bg=c["INPUT"], highlightthickness=1,
                                    highlightbackground=c["BORDER"])
                    new3.pack(fill="x", pady=(4, 12))
                    tk.Entry(new3, textvariable=pw2_var, bg=c["INPUT"], fg=c["FG"],
                             insertbackground=c["ACCENT"], relief="flat", bd=0,
                             font=("Cascadia Code", 11), show="●"
                             ).pack(fill="x", padx=12, pady=10)
                users = get_accounts()
                if users and mode_var.get() == "login":
                    lst = tk.Frame(frm, bg=c["BG"])
                    lst.pack(fill="x", pady=(4, 0))
                    tk.Label(lst, text=self.T["acc_existing"], bg=c["BG"],
                             fg=c["FG_DIM"], font=("Segoe UI", 8, "bold")
                             ).pack(anchor="w", pady=(0, 4))
                    names = ", ".join(u["name"] for u in users) or self.T["acc_none"]
                    tk.Label(lst, text=names, bg=c["BG"], fg=c["FG"],
                             font=("Cascadia Code", 9)).pack(anchor="w")
                br2 = tk.Frame(content, bg=c["BG"])
                br2.pack(fill="x", pady=(20, 0))

                def do_action():
                    nm = name_var.get().strip()
                    pw = pw_var.get()
                    if mode_var.get() == "login":
                        if verify_login(nm, pw):
                            set_current_user(nm)
                            messagebox.showinfo(self.T["acc_title"], self.T["acc_logged_in"])
                            dlg.destroy()
                            self._restart_app()
                        else:
                            messagebox.showerror(self.T["acc_title"], self.T["acc_wrong_pw"])
                    else:
                        pw2 = pw2_var.get()
                        if pw != pw2:
                            messagebox.showerror(self.T["acc_title"], self.T["acc_pw_mismatch"])
                            return
                        ok, err = create_account(nm, pw)
                        if ok:
                            set_current_user(nm)
                            messagebox.showinfo(self.T["acc_title"], self.T["acc_created"])
                            dlg.destroy()
                            self._restart_app()
                        else:
                            messagebox.showerror(self.T["acc_title"], err)

                RoundedButton(br2, self.T["acc_btn_login"] if is_login else self.T["acc_btn_register"],
                              do_action,
                              bg=c["ACCENT"], fg=c["ON_ACCENT"],
                              hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                              hover_fg=c["ON_ACCENT"], width=180, height=44,
                              canvas_bg=c["BG"]).pack(side="left", padx=(0, 8))
                RoundedButton(br2, self.T["acc_btn_cancel"], dlg.destroy,
                              bg=c["CARD_2"], fg=c["FG"],
                              hover_bg=c["BORDER"], hover_fg=c["FG"],
                              width=140, height=44, canvas_bg=c["BG"]).pack(side="left")
                en.focus_set()
                en.bind("<Return>", lambda e: do_action())
                ep.bind("<Return>", lambda e: do_action())

            render_form()

    def _action_logout(self):
        if not messagebox.askyesno(self.T["acc_title"], self.T["acc_confirm_logout"]):
            return
        set_current_user("")
        messagebox.showinfo(self.T["acc_title"], self.T["acc_logged_out"])
        self._restart_app()

    def _page_premium(self):
        c = self.C
        page = tk.Frame(self.content_wrap, bg=c["BG"])
        wrap = tk.Frame(page, bg=c["BG"])
        wrap.pack(fill="both", expand=True, padx=25, pady=20)
        h = tk.Frame(wrap, bg=c["BG"])
        h.pack(fill="x", pady=(0, 14))
        tk.Label(h, text=self.T["pr_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(h, text=self.T["pr_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))
        tr = tk.Frame(wrap, bg=c["BG"])
        tr.pack(fill="both", expand=True)
        ru = self.lang == "ru"
        free_features = (["\u0421\u043a\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435 Windows Defender",
                          "\u0411\u044b\u0441\u0442\u0440\u0430\u044f \u0438 \u043f\u043e\u043b\u043d\u0430\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430",
                          "\u0418\u0441\u0442\u043e\u0440\u0438\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043e\u043a"] if ru else
                         ["Windows Defender scanning", "Quick and full scans", "Scan history"])
        tester_features = (["\u0412\u0441\u0435 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u0438 Free",
                            "\u042d\u043a\u0441\u043f\u043e\u0440\u0442 \u0438\u0441\u0442\u043e\u0440\u0438\u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u043e\u043a \u0432 CSV",
                            "\u0417\u043d\u0430\u0447\u043e\u043a \u0442\u0435\u0441\u0442\u0435\u0440\u0430"] if ru else
                           ["Everything in Free", "Export scan history to CSV", "Tester badge"])
        self._tier_card(tr, "free", self.T["pr_free"],
                        "\u0412\u0441\u0435\u0433\u0434\u0430 \u0431\u0435\u0441\u043f\u043b\u0430\u0442\u043d\u043e" if ru else "Always free",
                        free_features, c["FG_DIM"], is_current=(self.tier == "free"))
        self._tier_card(tr, "tester", self.T["pr_tester"],
                        "\u0411\u0435\u0441\u043f\u043b\u0430\u0442\u043d\u043e \u043f\u043e \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u044e" if ru else "Free by invitation",
                        tester_features, c["ACCENT"], is_current=(self.tier == "tester"))
        cc = tk.Frame(wrap, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        cc.pack(fill="x", pady=(20, 0))
        ci = tk.Frame(cc, bg=c["CARD"])
        ci.pack(fill="x", padx=20, pady=16)
        tk.Label(ci, text=self.T["pr_code_label"], bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 10)).pack(side="left")
        RoundedButton(ci, self.T["pr_code_btn"], self.open_activate_dialog,
                      bg=c["ACCENT"], fg=c["ON_ACCENT"],
                      hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                      hover_fg=c["ON_ACCENT"], width=200, height=42,
                      canvas_bg=c["CARD"]).pack(side="right")
        return page

    def _tier_card(self, parent, tier_id, title, price, features, accent, is_current):
        c = self.C
        card = tk.Frame(parent, bg=c["CARD"], highlightthickness=2,
                        highlightbackground=accent if is_current else c["BORDER"])
        card.pack(side="left", fill="both", expand=True, padx=6)
        i = tk.Frame(card, bg=c["CARD"])
        i.pack(fill="both", expand=True, padx=20, pady=20)
        top = tk.Frame(i, bg=c["CARD"])
        top.pack(fill="x")
        tk.Label(top, text=title, bg=c["CARD"], fg=accent,
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        if is_current:
            tk.Label(top, text=self.T["pr_current"], bg=c["CARD"], fg=c["GREEN"],
                     font=("Segoe UI", 9, "bold")).pack(side="right")
        tk.Label(i, text=price, bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 28, "bold")).pack(anchor="w", pady=(12, 0))
        tk.Frame(i, bg=c["BORDER"], height=1).pack(fill="x", pady=14)
        for f in features:
            r = tk.Frame(i, bg=c["CARD"])
            r.pack(fill="x", pady=3)
            tk.Label(r, text="✓", bg=c["CARD"], fg=accent,
                     font=("Segoe UI", 10, "bold")).pack(side="left")
            tk.Label(r, text=f, bg=c["CARD"], fg=c["FG"],
                     font=("Segoe UI", 10)).pack(side="left", padx=(10, 0))
        if tier_id == "tester":
            action = self.export_scan_history if is_current else self.open_activate_dialog
            label = ("\u042d\u043a\u0441\u043f\u043e\u0440\u0442 \u0438\u0441\u0442\u043e\u0440\u0438\u0438 CSV" if self.lang == "ru" else "Export history CSV") if is_current else self.T["pr_buy"]
            RoundedButton(i, label, action,
                          bg=accent, fg=c["ON_ACCENT"],
                          hover_bg=lerp_color(accent, "#ffffff", 0.25),
                          hover_fg=c["ON_ACCENT"], width=200, height=42,
                          canvas_bg=c["CARD"]).pack(pady=(18, 0))
        else:
            tk.Label(i, text="", bg=c["CARD"]).pack(pady=(18, 0))

    def _page_about(self):
        c = self.C
        page = tk.Frame(self.content_wrap, bg=c["BG"])
        wrap = tk.Frame(page, bg=c["BG"])
        wrap.pack(fill="both", expand=True, padx=25, pady=20)
        h = tk.Frame(wrap, bg=c["BG"])
        h.pack(fill="x", pady=(0, 14))
        tk.Label(h, text=self.T["ab_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(h, text=self.T["ab_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))
        card = tk.Frame(wrap, bg=c["CARD"], highlightthickness=1,
                        highlightbackground=c["BORDER"])
        card.pack(fill="both", expand=True)
        i = tk.Frame(card, bg=c["CARD"])
        i.pack(fill="x", padx=30, pady=28)
        lr = tk.Frame(i, bg=c["CARD"])
        lr.pack(fill="x")
        sh = tk.Canvas(lr, width=90, height=90, bg=c["CARD"], highlightthickness=0)
        sh.pack(side="left")
        sh.create_oval(5, 5, 85, 85, fill=c["BG"], outline=c["ACCENT"], width=2)
        sh.create_text(45, 45, text="🛡", font=("Segoe UI Emoji", 36), fill=c["ACCENT"])
        sh.create_polygon(45, 15, 68, 24, 66, 49, 45, 73, 24, 49, 22, 24,
                          fill=c["ACCENT"], outline=c["ACCENT"], width=3,
                          joinstyle="round")
        sh.create_line(34, 43, 42, 51, 57, 34, fill=c["CARD"], width=4,
                       capstyle="round", joinstyle="round")
        tc = tk.Frame(lr, bg=c["CARD"])
        tc.pack(side="left", padx=(20, 0))
        tk.Label(tc, text=APP_NAME, bg=c["CARD"], fg=c["FG"],
                 font=("Segoe UI", 26, "bold")).pack(anchor="w")
        tk.Label(tc, text=f"v{APP_VERSION}", bg=c["CARD"], fg=c["ACCENT_2"],
                 font=("Cascadia Code", 10)).pack(anchor="w", pady=(2, 0))
        if self.lang == "ru":
            d = ("Легковесный антивирусный сканер на движке Microsoft Defender.\n"
                 "Не требует интернета, не собирает данные, работает локально.")
        else:
            d = ("Lightweight antivirus scanner powered by Microsoft Defender.\n"
                 "No internet required, no telemetry, runs fully offline.")
        tk.Label(tc, text=d, bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 9), justify="left").pack(anchor="w", pady=(8, 0))
        tk.Frame(i, bg=c["BORDER"], height=1).pack(fill="x", pady=22)
        g = tk.Frame(i, bg=c["CARD"])
        g.pack(fill="x")
        if self.lang == "ru":
            rows = [
                ("👤", "Разработчик", APP_AUTHOR),
                ("📦", "Версия", f"{APP_VERSION}  (build 2026.10)"),
                ("📅", "Дата релиза", "01.10.2026"),
                ("🔧", "Движок", "Microsoft Defender (MpCmdRun)"),
                ("💻", "Платформа", "Windows 10 / 11"),
                ("🎯", "Тип", "Антивирусный сканер"),
                ("🌐", "Локализация", "Русский · English"),
                ("📜", "Лицензия", "Freeware"),
                ("🚦", "Статус", "Beta — активная разработка"),
            ]
        else:
            rows = [
                ("👤", "Developer", APP_AUTHOR),
                ("📦", "Version", f"{APP_VERSION}  (build 2026.10)"),
                ("📅", "Release date", "October 2026"),
                ("🔧", "Engine", "Microsoft Defender (MpCmdRun)"),
                ("💻", "Platform", "Windows 10 / 11"),
                ("🎯", "Type", "Antivirus scanner"),
                ("🌐", "Localization", "Russian · English"),
                ("📜", "License", "Freeware"),
                ("🚦", "Status", "Beta — actively developed"),
            ]
        rows[0] = (rows[0][0], "Продукт" if self.lang == "ru" else "Product", APP_AUTHOR)
        about_icons = ("brand", "log", "about", "repair", "home",
                       "premium", "privacy", "about", "about")
        for index, (icon, key, val) in enumerate(rows):
            r = tk.Frame(g, bg=c["CARD"])
            r.pack(fill="x", pady=6)
            row_icon = tk.Canvas(r, width=22, height=22, bg=c["CARD"],
                                 highlightthickness=0)
            row_icon.pack(side="left")
            draw_ui_icon(row_icon, about_icons[index], c["ACCENT"])
            tk.Label(r, text=key, bg=c["CARD"], fg=c["FG_DIM"],
                     font=("Segoe UI", 10), width=18, anchor="w").pack(side="left", padx=(8, 0))
            tk.Label(r, text=val, bg=c["CARD"], fg=c["FG"],
                     font=("Segoe UI", 10, "bold"), anchor="w").pack(side="left", padx=(10, 0))
        tk.Frame(i, bg=c["BORDER"], height=1).pack(fill="x", pady=22)
        f = tk.Frame(i, bg=c["CARD"])
        f.pack(fill="x")
        note = ("© 2026  " + APP_NAME + "  ·  Все права защищены\n"
                "Продукт распространяется как есть, без гарантий."
                if self.lang == "ru" else
                "© 2026  " + APP_NAME + "  ·  All rights reserved\n"
                "Distributed as-is, without any warranty.")
        tk.Label(f, text=note, bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8), justify="left").pack(anchor="w")
        return page

    # ==================== АВТООБНОВЛЕНИЕ (UI) ====================
    def _check_for_updates(self, silent=True):
        def worker():
            info = fetch_update_info()
            if not info:
                if not silent:
                    self.root.after(0, lambda: messagebox.showinfo(
                        self.T["upd_check_title"], self.T["upd_check_fail"]))
                return
            remote = str(info.get("version", "")).strip()
            if not remote or not is_newer_version(remote, APP_VERSION):
                save_json(UPDATE_STATE_FILE, {
                    "last_check": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "remote_version": remote or APP_VERSION,
                })
                if not silent:
                    self.root.after(0, lambda: messagebox.showinfo(
                        self.T["upd_check_title"],
                        self.T["upd_check_latest"].format(v=APP_VERSION)))
                return
            save_json(UPDATE_STATE_FILE, {
                "last_check": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "remote_version": remote,
            })
            self.root.after(0, lambda: self._show_update_dialog(info))

        threading.Thread(target=worker, daemon=True).start()

    def _show_update_dialog(self, info):
        c = self.C
        remote = str(info.get("version", "")).strip()
        url = str(info.get("url", "")).strip()
        notes = str(info.get("notes") or "").strip()
        mandatory = bool(info.get("mandatory", False))
        sha_expected = str(info.get("sha256") or "").strip()
        if not url:
            return

        try:
            if self._update_dialog is not None and self._update_dialog.winfo_exists():
                self._update_dialog.lift()
                self._update_dialog.focus_force()
                return
        except Exception:
            pass

        try:
            if self.root.state() == "withdrawn" or not self.root.winfo_viewable():
                self._bring_to_front()
        except Exception:
            pass

        dlg = tk.Toplevel(self.root)
        self._update_dialog = dlg
        dlg.title(self.T["upd_title"])
        dlg.configure(bg=c["BG"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        w, h = 580, 540
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
        dlg.geometry(f"{w}x{h}+{x}+{y}")

        head = tk.Frame(dlg, bg=c["BG"])
        head.pack(fill="x", padx=25, pady=(20, 10))
        tk.Label(head, text="🚀", bg=c["BG"], fg=c["ACCENT"],
                 font=("Segoe UI Emoji", 26)).pack(side="left")
        ht = tk.Frame(head, bg=c["BG"])
        ht.pack(side="left", padx=(12, 0))
        tk.Label(ht, text=self.T["upd_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(ht, text=self.T["upd_sub"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

        vc = tk.Frame(dlg, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        vc.pack(fill="x", padx=25, pady=(10, 12))
        vi = tk.Frame(vc, bg=c["CARD"])
        vi.pack(fill="x", padx=18, pady=14)
        vr = tk.Frame(vi, bg=c["CARD"])
        vr.pack(fill="x")
        tk.Label(vr, text=self.T["upd_current"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Label(vr, text=f"  v{APP_VERSION}", bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Cascadia Code", 10)).pack(side="left")
        tk.Label(vr, text="→", bg=c["CARD"], fg=c["ACCENT"],
                 font=("Segoe UI", 12, "bold")).pack(side="left", padx=12)
        tk.Label(vr, text=f"v{remote}", bg=c["CARD"], fg=c["GREEN"],
                 font=("Cascadia Code", 11, "bold")).pack(side="left")
        if mandatory:
            tk.Label(vr, text=self.T["upd_mandatory"], bg=c["RED"], fg=c["ON_ACCENT"],
                     font=("Segoe UI", 8, "bold"), padx=8, pady=2
                     ).pack(side="right")

        nw = tk.Frame(dlg, bg=c["CARD"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        nw.pack(fill="both", expand=True, padx=25, pady=(0, 12))
        ni = tk.Frame(nw, bg=c["CARD"])
        ni.pack(fill="both", expand=True, padx=18, pady=14)
        tk.Label(ni, text=self.T["upd_whatsnew"], bg=c["CARD"], fg=c["FG_DIM"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        nt = tk.Text(ni, bg=c["CARD"], fg=c["FG"], font=("Segoe UI", 10),
                     relief="flat", bd=0, wrap="word", height=8,
                     highlightthickness=0, padx=0, pady=0)
        nt.pack(fill="both", expand=True, pady=(8, 0))
        nt.insert("1.0", notes or self.T["upd_no_notes"])
        nt.configure(state="disabled")

        prog_wrap = tk.Frame(dlg, bg=c["BG"])
        prog_wrap.pack(fill="x", padx=25, pady=(0, 8))
        status_lbl = tk.Label(prog_wrap, text="", bg=c["BG"], fg=c["FG_DIM"],
                              font=("Cascadia Code", 9))
        status_lbl.pack(anchor="w")
        pbar = ttk.Progressbar(prog_wrap, style="Product.Horizontal.TProgressbar",
                               mode="determinate", maximum=100, value=0)

        state = {"cancelled": False}

        br = tk.Frame(dlg, bg=c["BG"])
        br.pack(fill="x", padx=25, pady=(8, 20))

        def do_close():
            if mandatory:
                if not messagebox.askyesno(self.T["upd_title"],
                                           self.T["upd_mandatory_warn"], parent=dlg):
                    return
            state["cancelled"] = True
            try:
                dlg.destroy()
            except Exception:
                pass
            self._update_dialog = None

        def show_fail(err):
            status_lbl.configure(text=f"❌ {self.T['upd_failed']}", fg=c["RED"])
            try:
                pbar.pack_forget()
            except Exception:
                pass
            btn_update.set_enabled(True)
            btn_later.set_enabled(True)
            messagebox.showerror(self.T["upd_failed"], err, parent=dlg)

        def start_download():
            btn_update.set_enabled(False)
            btn_later.set_enabled(False)
            status_lbl.configure(text=self.T["upd_downloading"], fg=c["ACCENT"])
            pbar.pack(fill="x", pady=(6, 0))
            pbar.configure(value=0)

            def progress_cb(done, total):
                if state["cancelled"]:
                    return
                if total > 0:
                    pct = done * 100.0 / total
                    txt = (f"{done / 1048576.0:.1f} / {total / 1048576.0:.1f} MB"
                           f"   ·   {int(pct)}%")
                else:
                    pct = 0
                    txt = f"{done / 1048576.0:.1f} MB"

                def upd():
                    try:
                        pbar.configure(value=pct)
                        status_lbl.configure(text=txt)
                    except Exception:
                        pass
                self.root.after(0, upd)

            def worker():
                ext = os.path.splitext(url.split("?")[0])[1] or ".exe"
                tmp = os.path.join(os.environ.get("TEMP", CONFIG_DIR),
                                   f"SentryX_update_{uuid.uuid4().hex}{ext}")
                ok, err = download_file(url, tmp, progress_cb=progress_cb)
                if state["cancelled"]:
                    try:
                        if os.path.exists(tmp):
                            os.remove(tmp)
                    except Exception:
                        pass
                    return
                if not ok:
                    self.root.after(0, lambda e=err: show_fail(e))
                    return
                if sha_expected:
                    self.root.after(0, lambda: status_lbl.configure(
                        text="🔐 Проверяю целостность...", fg=c["ACCENT"]))
                    ok_sha, err_sha = verify_sha256(tmp, sha_expected)
                    if not ok_sha:
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
                        self.root.after(0, lambda e=err_sha: show_fail(
                            f"{self.T['upd_sha_fail']}\n\n{e}"))
                        return
                self.root.after(0, lambda: status_lbl.configure(
                    text=self.T["upd_installing"], fg=c["GREEN"]))
                time.sleep(0.4)
                ok2, err2 = apply_update_and_restart(tmp)
                if not ok2:
                    self.root.after(0, lambda e=err2: show_fail(e))
                    return
                self.root.after(0, self._do_quit)

            threading.Thread(target=worker, daemon=True).start()

        btn_update = RoundedButton(br, self.T["upd_btn_update"], start_download,
                                    bg=c["GREEN"], fg=c["ON_ACCENT"],
                                    hover_bg=lerp_color(c["GREEN"], "#ffffff", 0.25),
                                    hover_fg=c["ON_ACCENT"],
                                    width=210, height=46, canvas_bg=c["BG"])
        btn_update.pack(side="right", padx=(8, 0))
        btn_later = RoundedButton(br, self.T["upd_btn_later"], do_close,
                                   bg=c["CARD_2"], fg=c["FG"],
                                   hover_bg=c["BORDER"], hover_fg=c["FG_DIM"],
                                   width=140, height=46, canvas_bg=c["BG"])
        btn_later.pack(side="right")

    def _build_statusbar(self):
        c = self.C
        bar = tk.Frame(self.root, bg=c["CARD"], height=64)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Frame(bar, bg=c["BORDER"], height=1).pack(fill="x", side="top")
        left = tk.Frame(bar, bg=c["CARD"])
        left.pack(side="left", padx=15)
        self.dot = tk.Canvas(left, width=22, height=22, bg=c["CARD"],
                             highlightthickness=0)
        self.dot.pack(side="left")
        self.status = tk.Label(left, text=self.T["status_ready"], bg=c["CARD"],
                               fg=c["FG_DIM"], font=("Segoe UI", 9))
        self.status.pack(side="left", padx=(8, 0))
        cf = tk.Frame(bar, bg=c["CARD"])
        cf.pack(side="left", fill="x", expand=True, padx=(20, 150))
        self.progress = ttk.Progressbar(cf, style="Product.Horizontal.TProgressbar",
                                        mode="indeterminate")
        self.progress_hint = tk.Label(cf, text="", bg=c["CARD"], fg=c["FG_DIM"],
                                      font=("Cascadia Code", 8))
        self.btn_stop = RoundedButton(bar, self.T["btn_stop"], self.stop_scan,
                                      bg=c["CARD_2"], fg=c["RED"],
                                      hover_bg=lerp_color(c["CARD_2"], c["RED"], 0.2),
                                      hover_fg=c["ON_ACCENT"], width=124, height=38,
                                      radius=10, font=("Segoe UI", 9, "bold"),
                                      canvas_bg=c["CARD"])
        self.btn_stop.place(relx=1.0, x=-12, y=10, anchor="ne")
        self.btn_stop.set_enabled(False)

    def _pulse_status(self):
        if not hasattr(self, "dot") or not self.dot.winfo_exists():
            return
        self.pulse_phase += 1
        c = self.C
        try:
            self.dot.delete("all")
            if self.is_scanning:
                angle = (self.pulse_phase * 8) % 360
                self.dot.create_arc(2, 2, 20, 20, start=angle, extent=270,
                                    outline=c["ACCENT"], width=3, style="arc")
            else:
                self.dot.create_oval(7, 7, 15, 15, fill=c["GREEN"], outline="")
        except Exception:
            pass
        self._pulse_job = self.root.after(40, self._pulse_status)

    def _log(self, text, tag=None):
        self.log_lines.append((text, tag))
        if hasattr(self, "log") and self.log.winfo_exists():
            self._render_filtered_log()

    def _log_divider(self):
        self._log("─" * 60, "dim")

    def _restore_log(self):
        self._render_filtered_log()

    def _set_status(self, text, color=None):
        if not hasattr(self, "status") or not self.status.winfo_exists():
            return
        if color is None:
            color = self.C["FG_DIM"]
        self.status.configure(text=text, fg=color)

    def set_theme(self, theme):
        if theme == self.theme:
            return
        self.theme = theme
        self._save_config()
        self._rebuild_preserve()

    def set_lang(self, lang):
        if lang == self.lang:
            return
        self.lang = lang
        self._save_config()
        if self.tray:
            try:
                self.tray.menu = pystray.Menu(
                    pystray.MenuItem(self.T["tray_open"], self._tray_show, default=True),
                    pystray.MenuItem(self.T["tray_scan"], self._tray_quick_scan),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(self.T["tray_exit"], self._tray_quit))
                self.tray.title = self.T["tray_tooltip"]
            except Exception:
                pass
        self._rebuild_preserve()

    def _rebuild_preserve(self):
        if hasattr(self, "folder_var"):
            try:
                self.folder_path = self.folder_var.get()
            except Exception:
                pass
        self._save_config()
        self.root.configure(bg=self.C["BG"])
        self._build_main()
        self.show_page(self.page)

    def refresh_settings(self):
        if not hasattr(self, "settings_status") or not self.settings_status.winfo_exists():
            return
        c = self.C
        if not DEFENDER_EXE:
            self.settings_status.configure(text=self.T["def_not_found"], fg=c["RED"])
            return
        info = get_defender_status()
        if not info:
            self.settings_status.configure(text="⚠  N/A", fg=c["YELLOW"])
            return
        parts = dict(p.split("=") for p in info.split(";") if "=" in p)
        av = parts.get("AV", "?")
        rt = parts.get("RT", "?")
        age = parts.get("SigAge", "?")
        ver = parts.get("SigVer", "?")
        astr = "✅" if av == "True" else "❌"
        rstr = "✅" if rt == "True" else "❌"
        if self.lang == "ru":
            text = (f"Антивирус:                  {astr}\n"
                    f"Защита в реальном времени:  {rstr}\n"
                    f"Возраст баз:                {age} дн.\n"
                    f"Версия баз:                 {ver}")
        else:
            text = (f"Antivirus:                  {astr}\n"
                    f"Real-time protection:       {rstr}\n"
                    f"Signature age:              {age} days\n"
                    f"Signature version:          {ver}")
        color = c["GREEN"] if av == "True" and rt == "True" else c["YELLOW"]
        self.settings_status.configure(text=text, fg=color)

    def choose_folder(self):
        path = filedialog.askdirectory(initialdir=self.folder_path)
        if path:
            self.folder_var.set(path)
            self.folder_path = path
            self._save_config()

    def _show_progress(self):
        try:
            self.progress.pack(fill="x", expand=True, pady=(4, 0))
            self.progress_hint.pack()
            self.progress.start(12)
        except Exception:
            pass

    def _hide_progress(self):
        try:
            self.progress.stop()
            self.progress.pack_forget()
            self.progress_hint.pack_forget()
        except Exception:
            pass

    def _prepare_scan(self, title):
        self.log_lines = []
        if hasattr(self, "log") and self.log.winfo_exists():
            self.log.configure(state="normal")
            self.log.delete("1.0", "end")
            self.log.configure(state="disabled")
        self.stop_flag = False
        self.is_scanning = True
        self.threats_found = 0
        self.live_counter_stop = False
        self.btn_folder.set_enabled(False)
        self.btn_quick.set_enabled(False)
        self.btn_full.set_enabled(False)
        self.btn_file.set_enabled(False)
        self.btn_stop.set_enabled(True)
        self.progress_hint.configure(text="")
        self._show_progress()
        self._set_status(title, self.C["ACCENT"])
        self.show_page("log")

    def _count_files(self, path):
        if not path or not os.path.exists(path):
            return 0
        if os.path.isfile(path):
            return 1
        n = 0
        try:
            for _, _, fs in os.walk(path):
                n += len(fs)
        except Exception:
            pass
        return n

    def _live_counter_thread(self, total, dur, label):
        start = time.time()
        while not self.live_counter_stop and self.is_scanning:
            el = time.time() - start
            p = min(0.99, el / dur) if dur > 0 else 0
            cur = int(total * p)
            txt = (self.T["scan_counter"].format(cur=cur, total=total) if total > 0
                   else self.T["scan_counter_files"].format(cur=cur))
            txt += "   ·   " + self.T["scan_elapsed"].format(
                t=time.strftime("%M:%S", time.gmtime(el)))
            try:
                self.root.after(0, lambda t=txt: self.progress_hint.configure(text=t))
            except Exception:
                return
            time.sleep(0.4)

    def start_folder_scan(self):
        f = self.folder_var.get()
        if not os.path.isdir(f):
            messagebox.showerror(self.T["err_title"], self.T["err_folder"])
            return
        self._prepare_scan(self.T["scan_launch"].format(label=self.T["label_folder"]))
        t = self._count_files(f)
        e = max(30, min(1800, t / 200.0))
        threading.Thread(target=self._live_counter_thread, args=(t, e, "folder"),
                         daemon=True).start()
        threading.Thread(target=self._scan_worker,
                         args=(3, f, self.T["label_folder"], t, time.time()),
                         daemon=True).start()

    def start_quick_scan(self):
        self._prepare_scan(self.T["scan_launch"].format(label=self.T["label_quick"]))
        threading.Thread(target=self._live_counter_thread, args=(0, 60, "quick"),
                         daemon=True).start()
        threading.Thread(target=self._scan_worker,
                         args=(1, None, self.T["label_quick"], 0, time.time()),
                         daemon=True).start()

    def start_full_scan(self):
        if not messagebox.askyesno(self.T["ask_full_title"], self.T["ask_full_text"]):
            return
        self._prepare_scan(self.T["scan_launch"].format(label=self.T["label_full"]))
        threading.Thread(target=self._live_counter_thread, args=(0, 1800, "full"),
                         daemon=True).start()
        threading.Thread(target=self._scan_worker,
                         args=(2, None, self.T["label_full"], 0, time.time()),
                         daemon=True).start()

    def start_file_scan(self):
        p = filedialog.askopenfilename(title=self.T["btn_file"])
        if not p:
            return
        self._scan_specific_file(p)

    def _scan_specific_file(self, path):
        if not os.path.isfile(path):
            messagebox.showerror(self.T["err_title"], "Файл не найден")
            return
        self._prepare_scan(self.T["scan_launch"].format(label=self.T["label_file"]))
        threading.Thread(target=self._live_counter_thread, args=(1, 10, "file"),
                         daemon=True).start()
        threading.Thread(target=self._scan_worker,
                         args=(3, path, self.T["label_file"], 1, time.time()),
                         daemon=True).start()

    def stop_scan(self):
        self.stop_flag = True
        self.live_counter_stop = True
        self._set_status(self.T["status_stopping"], self.C["YELLOW"])

    def update_signatures(self):
        if self.is_scanning:
            messagebox.showinfo(self.T["msg_wait"], self.T["msg_wait_text"])
            return

        def w():
            self.root.after(0, self._log, self.T["upd_start"], "info")
            self.root.after(0, self._log, self.T["upd_time"], "dim")
            self.root.after(0, self._log_divider)
            rc, o, e = update_defender_signatures()
            if rc == 0:
                self.root.after(0, self._log, self.T["upd_ok"], "ok")
            else:
                self.root.after(0, self._log, self.T["upd_err"], "mal")
                if e:
                    self.root.after(0, self._log, f"   {e.strip()[:200]}", "dim")
            self.root.after(0, self._log_divider)
            self.root.after(0, self.refresh_settings)
        self.show_page("log")
        threading.Thread(target=w, daemon=True).start()

    def open_activate_dialog(self):
        c = self.C
        dlg = tk.Toplevel(self.root)
        dlg.title(self.T["pr_dialog_title"])
        dlg.configure(bg=c["BG"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        w, h = 420, 280
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
        dlg.geometry(f"{w}x{h}+{x}+{y}")
        tk.Label(dlg, text=self.T["pr_dialog_title"], bg=c["BG"], fg=c["FG"],
                 font=("Segoe UI", 14, "bold")).pack(pady=(20, 4))
        tk.Label(dlg, text=self.T["pr_dialog_hint"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Segoe UI", 10)).pack()
        cv = tk.StringVar()
        ew = tk.Frame(dlg, bg=c["INPUT"], highlightthickness=1,
                      highlightbackground=c["BORDER"])
        ew.pack(padx=30, pady=14, fill="x")
        e = tk.Entry(ew, textvariable=cv, bg=c["INPUT"], fg=c["FG"],
                     insertbackground=c["ACCENT"], relief="flat", bd=0,
                     font=("Cascadia Code", 11), justify="center")
        e.pack(fill="x", padx=12, pady=10)
        e.focus_set()
        tk.Label(dlg, text=self.T["pr_demo_hint"], bg=c["BG"], fg=c["FG_DIM"],
                 font=("Cascadia Code", 8), justify="center").pack()
        br = tk.Frame(dlg, bg=c["BG"])
        br.pack(pady=16)

        def act():
            cd = cv.get().strip().upper()
            if not cd:
                messagebox.showwarning(self.T["err_title"], self.T["pr_code_empty"],
                                       parent=dlg)
                return
            if is_tester_invite(cd):
                self.tier = "tester"
                messagebox.showinfo(self.T["pr_title"], self.T["pr_activated_tester"])
                dlg.destroy()
                self._save_config()
                self._rebuild_preserve()
            else:
                messagebox.showerror(self.T["err_title"], self.T["pr_code_wrong"],
                                     parent=dlg)

        RoundedButton(br, self.T["pr_btn_activate"], act,
                      bg=c["ACCENT"], fg=c["ON_ACCENT"],
                      hover_bg=lerp_color(c["ACCENT"], "#ffffff", 0.25),
                      hover_fg=c["ON_ACCENT"], width=160, height=42,
                      canvas_bg=c["BG"]).pack(side="left", padx=6)
        RoundedButton(br, self.T["pr_btn_cancel"], dlg.destroy,
                      bg=c["CARD_2"], fg=c["FG"],
                      hover_bg=c["BORDER"], hover_fg=c["RED"],
                      width=160, height=42, canvas_bg=c["BG"]).pack(side="left", padx=6)
        e.bind("<Return>", lambda ev: act())

    def export_scan_history(self):
        if self.tier != "tester":
            return
        scans = load_json(HISTORY_FILE, {"scans": []}).get("scans", [])
        if not scans:
            messagebox.showinfo(self.T["pr_title"],
                                "\u0418\u0441\u0442\u043e\u0440\u0438\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043e\u043a \u043f\u043e\u043a\u0430 \u043f\u0443\u0441\u0442\u0430." if self.lang == "ru"
                                else "There are no scans to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="\u042d\u043a\u0441\u043f\u043e\u0440\u0442 \u0438\u0441\u0442\u043e\u0440\u0438\u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u043e\u043a" if self.lang == "ru" else "Export scan history",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
            initialfile="SentryX-scan-history.csv")
        if not path:
            return
        fields = ("date", "type", "files", "threats", "duration", "result")
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as output:
                writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(scans)
            messagebox.showinfo(self.T["pr_title"],
                                "\u0418\u0441\u0442\u043e\u0440\u0438\u044f \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0430 \u0432 CSV." if self.lang == "ru"
                                else "Scan history exported to CSV.")
        except OSError as exc:
            messagebox.showerror(self.T["err_title"], str(exc))
    def _scan_worker(self, st, target, label, tf, t0):
        self.root.after(0, self._log, self.T["scan_launch"].format(label=label), "info")
        if target:
            self.root.after(0, self._log, f"   {target}", "dim")
        self.root.after(0, self._log, self.T["scan_wait"], "warn")
        self.root.after(0, self._log_divider)
        rc, o, e = run_defender_scan(st, target)
        dur = time.time() - t0
        th = self._parse_defender_output(o)
        self.live_counter_stop = True
        if self.stop_flag:
            res = "stopped"
        elif rc == 0 and th == 0:
            res = "clean"
            self.root.after(0, self._log, self.T["scan_clean"], "ok")
        elif rc == 2 or th > 0:
            res = "danger"
            self.root.after(0, self._log, self.T["scan_threats"].format(n=th or "?"), "mal")
            self.threats_found = th
        else:
            res = "error"
            if e:
                self.root.after(0, self._log, f"⚠  {e.strip()[:200]}", "warn")
            if o:
                for line in o.strip().split("\n")[-15:]:
                    self.root.after(0, self._log, f"   {line}", "dim")
        self._add_history(label, tf, th, dur, res)
        if st == 3 and target and os.path.isfile(target) and th > 0:
            self.root.after(0, self._offer_quarantine, target)
        self.root.after(0, self._done)

    def _offer_quarantine(self, fp):
        if messagebox.askyesno(self.T["quar_title"],
                               self.T["quar_threat_q"].format(name=os.path.basename(fp))):
            if quarantine_add(fp):
                messagebox.showinfo(self.T["quar_title"], self.T["quar_added"])
                self._render_quarantine()

    def _parse_defender_output(self, text):
        if not text:
            return 0
        c = 0
        for ln in text.split("\n"):
            lw = ln.lower()
            if any(k in lw for k in ["threat", "virus", "malware", "trojan",
                                     "found ", "обнаруж", "угроз"]):
                if "no threat" in lw or "не обнаруж" in lw or "found no" in lw:
                    continue
                if re.search(r"\d+", ln):
                    c += 1
        return c

    def _done(self):
        self.is_scanning = False
        self.live_counter_stop = True
        self._hide_progress()
        self.btn_folder.set_enabled(True)
        self.btn_quick.set_enabled(True)
        self.btn_full.set_enabled(True)
        self.btn_file.set_enabled(True)
        self.btn_stop.set_enabled(False)
        self._log_divider()
        if self.threats_found > 0:
            self._log(self.T["scan_result_threats"].format(n=self.threats_found), "mal")
            self._set_status(f"⚠  {self.threats_found}", self.C["RED"])
        else:
            self._log(self.T["scan_result"], "ok")
            self._set_status(self.T["status_done_clean"], self.C["GREEN"])
        try:
            hidden = (not self.root.winfo_viewable()) or self.root.state() == "withdrawn"
        except Exception:
            hidden = False
        if hidden:
            if self.threats_found > 0:
                self._notify(self.T["notify_title"],
                             self.T["notify_threats"].format(n=self.threats_found))
            else:
                self._notify(self.T["notify_title"], self.T["notify_clean"])
        if self.page == "home":
            self._rebuild_preserve()


if HAS_WATCHDOG:
    class DownloadsHandler(FileSystemEventHandler):
        def __init__(self, app):
            self.app = app

        def on_created(self, event):
            if event.is_directory:
                return
            path = event.src_path
            name = os.path.basename(path).lower()
            if name.endswith((".tmp", ".part", ".crdownload", ".partial")):
                return
            threading.Timer(3.0, self._delayed_scan, args=[path]).start()

        def on_moved(self, event):
            if event.is_directory:
                return
            self.on_created(event)

        def _delayed_scan(self, path):
            if not os.path.exists(path):
                return
            try:
                s1 = os.path.getsize(path)
                time.sleep(1.5)
                if not os.path.exists(path):
                    return
                if os.path.getsize(path) != s1:
                    return
            except Exception:
                return
            try:
                self.app.root.after(0, lambda: self.app._auto_scan_file(path))
            except Exception:
                pass


def _relaunch_as_admin():
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = ""
        else:
            exe = _get_gui_python_executable()
            script = os.path.abspath(__file__)
            params = f'"{script}"'

        if len(sys.argv) >= 3 and sys.argv[1] == "--scan":
            target = sys.argv[2].replace('"', '\\"')
            params += f' --scan "{target}"'

        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, None, 1)
        return ret > 32
    except Exception:
        return False


if __name__ == "__main__":
    if _relaunch_without_console():
        sys.exit(0)

    _init_paths()

    if not is_admin():
        if _relaunch_as_admin():
            sys.exit(0)

    startup_target = None
    if len(sys.argv) >= 3 and sys.argv[1] == "--scan":
        startup_target = sys.argv[2]
    is_first = try_acquire_single_instance()
    if not is_first:
        if startup_target:
            send_path_to_running_instance(startup_target)
        sys.exit(0)
    root = tk.Tk()
    app = SentryXApp(root, startup_scan=startup_target)
    root.mainloop()
