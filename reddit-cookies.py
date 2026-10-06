#!/usr/bin/env python3
"""Снять сессию Reddit на маке Антона и положить её в файл для Sanja.

Зачем: отправка в Reddit (личка, комментарии) требует сессионных cookie.
Логин через брокера redditapis.com падает на их стороне (UPSTREAM_ERROR —
Reddit не даёт вердикта по паролю, 6 попыток 06.10.2026), а запрашивать
у Reddit токен напрямую нельзя: script-app на prefs/apps не создаётся
по их Responsible Builder Policy, и с IP датацентра эти страницы отдают 403.
Живой браузер человека обходит всё это целиком.

Два режима, по порядку:
  1. ТИХИЙ — читает cookie из уже залогиненного Chrome/Brave/Edge/Chromium.
     Ничего открывать и вводить не нужно. macOS спросит доступ к Keychain
     («python хочет использовать Chrome Safe Storage») — это и есть
     расшифровка cookie, нажать «Разрешить».
  2. ОКНО — если в тихом режиме сессии нет: ставит Playwright и открывает
     Chromium на странице входа. Входить ЛОГИНОМ И ПАРОЛЕМ, не кнопкой
     Google: Google часто блокирует вход в автоматизированном браузере.

Результат: ~/Desktop/reddit-session.json — его и прислать Sanja в чат.
Внутри живые ключи доступа к аккаунту, срок жизни около суток.

Запуск на маке:
    python3 ~/Desktop/reddit-cookies.py
    python3 ~/Desktop/reddit-cookies.py --window    # сразу окно, без Chrome
"""
import getpass
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

NEED = ("reddit_session", "loid", "csrf_token", "token_v2")
OUT = os.path.expanduser("~/Desktop/reddit-session.json")

# Профили браузеров на macOS: путь к базе cookie + имя записи в Keychain.
BROWSERS = [
    ("Chrome", "~/Library/Application Support/Google/Chrome", "Chrome Safe Storage", "Chrome"),
    ("Chrome Beta", "~/Library/Application Support/Google/Chrome Beta", "Chrome Safe Storage", "Chrome"),
    ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser", "Brave Safe Storage", "Brave"),
    ("Edge", "~/Library/Application Support/Microsoft Edge", "Microsoft Edge Safe Storage", "Microsoft Edge"),
    ("Chromium", "~/Library/Application Support/Chromium", "Chromium Safe Storage", "Chromium"),
    ("Arc", "~/Library/Application Support/Arc/User Data", "Arc Safe Storage", "Arc"),
]


def say(*a):
    print(*a, flush=True)


def keychain_key(service, account):
    """Пароль шифрования cookie из Keychain. Вернёт None, если отказали."""
    try:
        r = subprocess.run(["security", "find-generic-password", "-w", "-s", service, "-a", account],
                           capture_output=True, text=True, timeout=120)
        return r.stdout.strip() or None
    except Exception:
        return None


def aes_cbc_decrypt(key_bytes, blob):
    """AES-128-CBC через openssl CLI: на свежем маке нет ни pycryptodome,
    ни cryptography, а ставить пакеты ради одного запуска — лишнее."""
    iv = b" " * 16
    try:
        r = subprocess.run(
            ["openssl", "enc", "-d", "-aes-128-cbc", "-nopad",
             "-K", key_bytes.hex(), "-iv", iv.hex()],
            input=blob, capture_output=True, timeout=60)
        return r.stdout
    except Exception:
        return b""


def clean(plain):
    """Убрать PKCS7-паддинг и, у новых Chrome, 32 байта хеша домена в начале."""
    if not plain:
        return None
    pad = plain[-1]
    if 1 <= pad <= 16:
        plain = plain[:-pad]
    for candidate in (plain, plain[32:]):
        try:
            s = candidate.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s and all(32 <= ord(c) < 127 for c in s):
            return s
    return None


def from_browser():
    """Тихий режим: вытащить cookie reddit.com из баз установленных браузеров."""
    for name, base, service, account in BROWSERS:
        base = os.path.expanduser(base)
        if not os.path.isdir(base):
            continue
        dbs = []
        for prof in ("Default", "Profile 1", "Profile 2", "Profile 3"):
            p = os.path.join(base, prof, "Cookies")
            if os.path.exists(p):
                dbs.append((prof, p))
        if not dbs:
            continue
        say(f"· {name}: профилей с cookie — {len(dbs)}")
        pw = keychain_key(service, account)
        if not pw:
            say(f"  Keychain не дал ключ для {name} (отказ или нет записи) — пропускаю")
            continue
        import hashlib
        key = hashlib.pbkdf2_hmac("sha1", pw.encode(), b"saltysalt", 1003, 16)
        for prof, db in dbs:
            tmp = os.path.join(tempfile.mkdtemp(), "Cookies")
            try:
                shutil.copy2(db, tmp)  # копия: живую базу Chrome держит под замком
                con = sqlite3.connect(tmp)
                rows = con.execute(
                    "SELECT host_key, name, encrypted_value FROM cookies "
                    "WHERE host_key LIKE '%reddit.com%'").fetchall()
                con.close()
            except Exception as e:
                say(f"  {prof}: базу прочитать не вышло ({e})")
                continue
            got = {}
            for host, cname, ev in rows:
                if cname not in NEED or not ev:
                    continue
                val = clean(aes_cbc_decrypt(key, ev[3:] if ev[:3] in (b"v10", b"v11") else ev))
                if val and (cname not in got or len(val) > len(got[cname])):
                    got[cname] = val
            if got.get("reddit_session"):
                say(f"  {prof}: нашла {', '.join(sorted(got))}")
                return got, f"{name} / {prof}"
            if rows:
                say(f"  {prof}: cookie reddit есть, но сессии среди них нет (не залогинен в этом профиле)")
    return None, None


def from_window():
    """Режим окна: открыть Chromium, дождаться входа, забрать cookie."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        say("\nСтавлю Playwright (один раз, минуты две)…")
        subprocess.run([sys.executable, "-m", "pip", "install", "--user", "--quiet", "playwright"], check=False)
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=False)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            sys.exit("Playwright не встал. Напиши Sanja — сделаем иначе.")

    say("\nОткрываю окно Chromium на странице входа Reddit.")
    say("🔴 Входить ЛОГИНОМ И ПАРОЛЕМ, не кнопкой Google: Google блокирует")
    say("   вход в автоматизированных браузерах.")
    with sync_playwright() as p:
        br = p.chromium.launch(headless=False, args=["--disable-blink-features=AutomationControlled"])
        ctx = br.new_context(viewport={"width": 1180, "height": 820},
                             locale="en-US", timezone_id="America/Recife")
        page = ctx.new_page()
        page.goto("https://www.reddit.com/login/", wait_until="domcontentloaded")
        say("\nКогда войдёшь — вернись в терминал и нажми Enter.")
        try:
            input()
        except EOFError:
            pass
        got = {}
        for c in ctx.cookies():
            if "reddit.com" in c.get("domain", "") and c["name"] in NEED:
                if c["name"] not in got or len(c["value"]) > len(got[c["name"]]):
                    got[c["name"]] = c["value"]
        try:
            who = page.evaluate("() => (window.___r && window.___r.user "
                                "&& window.___r.user.account && window.___r.user.account.displayText) || null")
        except Exception:
            who = None
        br.close()
    return got, f"окно Chromium{' / ' + who if who else ''}"


def main():
    say("Снимаю сессию Reddit для Sanja.\n")
    got, where = (None, None) if "--window" in sys.argv else from_browser()
    if not got:
        if "--window" not in sys.argv:
            say("\nВ браузерах готовой сессии не нашлось — открываю окно.")
        got, where = from_window()

    missing = [n for n in ("reddit_session", "loid", "csrf_token") if not got.get(n)]
    if not got.get("reddit_session"):
        sys.exit("\n🔴 Сессии нет: reddit_session не найден. Значит вход не завершился. "
                 "Запусти ещё раз с ключом --window и войди логином и паролем.")

    payload = {"source": where, "user": getpass.getuser(), "cookies": got,
               "taken_at": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                                          capture_output=True, text=True).stdout.strip()}
    with open(OUT, "w") as fh:
        json.dump(payload, fh, indent=1)
    os.chmod(OUT, 0o600)

    say("\n" + "=" * 54)
    say(f"Готово. Файл: {OUT}")
    say(f"Откуда: {where}")
    say("Есть: " + ", ".join(sorted(got)))
    if missing:
        say("Нет: " + ", ".join(missing) + " — пришли файл как есть, разберусь, хватит ли")
    say("\nОтправь этот файл Sanja в чат. Внутри живые ключи доступа")
    say("к аккаунту со сроком около суток — после отправки файл можно удалить.")
    say("=" * 54)


if __name__ == "__main__":
    main()
