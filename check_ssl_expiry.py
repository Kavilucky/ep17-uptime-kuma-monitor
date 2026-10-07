#!/usr/bin/env python3
"""Проверка срока SSL-сертификатов сайтов: второй рубеж рядом с Uptime Kuma.

Примеры:
  python check_ssl_expiry.py example.com
  python check_ssl_expiry.py example.com shop.example.org:8443 --warn-days 14
  python check_ssl_expiry.py --file sites.txt --telegram

Код возврата: 0 всё в порядке, 1 есть сертификаты, срок которых меньше порога, 2 есть недоступные или недействительные.
Только стандартная библиотека Python 3.9+. Сайты опрашиваются только теми адресами, которые вы сами указали.
С ключом --telegram итог уходит в вашего бота (переменные TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID); без ключа ничего не отправляется.
"""
import argparse
import datetime
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def parse_target(raw):
    raw = raw.strip()
    raw = raw.replace("https://", "").replace("http://", "").split("/")[0]
    host, _, port = raw.partition(":")
    return host, int(port) if port else 443


def days_left(host, port, timeout):
    """Вернуть (дней до окончания, дата окончания). Исключение при ошибке соединения или проверки."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    not_after = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), datetime.timezone.utc)
    delta = not_after - datetime.datetime.now(datetime.timezone.utc)
    return delta.days, not_after


def check_one(target, warn_days, timeout):
    host, port = parse_target(target)
    name = host if port == 443 else f"{host}:{port}"
    try:
        left, until = days_left(host, port, timeout)
    except ssl.SSLCertVerificationError as e:
        return 2, f"ОШИБКА  {name}: сертификат недействителен или просрочен ({e.verify_message})"
    except (OSError, ssl.SSLError, ValueError, KeyError) as e:
        return 2, f"НЕТ ДАННЫХ  {name}: {e.__class__.__name__}: {e}"
    when = until.strftime("%Y-%m-%d")
    if left < 0:
        return 2, f"ПРОСРОЧЕН  {name}: истёк {when}"
    if left < warn_days:
        return 1, f"СКОРО  {name}: осталось {left} дн. (до {when}), порог {warn_days}"
    return 0, f"OK  {name}: осталось {left} дн. (до {when})"


def send_telegram(text):
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        print("Telegram: заданы не все переменные TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID, сообщение не отправлено.", file=sys.stderr)
        return
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
    try:
        urllib.request.urlopen(req, timeout=15).read()
        print("Telegram: сообщение отправлено.")
    except Exception as e:  # токен в сообщение об ошибке не выводим
        print(f"Telegram: не удалось отправить ({e.__class__.__name__}).", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Проверка срока SSL-сертификатов", epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="сайты: example.com или example.com:8443")
    ap.add_argument("--file", help="файл со списком сайтов, по одному в строке (# комментарии)")
    ap.add_argument("--warn-days", type=int, default=14, help="предупреждать, если осталось меньше дней (по умолчанию 14)")
    ap.add_argument("--timeout", type=float, default=10.0, help="таймаут соединения, с")
    ap.add_argument("--telegram", action="store_true", help="отправить проблемы в вашего Telegram-бота")
    a = ap.parse_args()

    targets = list(a.targets)
    if a.file:
        with open(a.file, encoding="utf-8") as f:
            targets += [ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()]
    if not targets:
        ap.error("укажите сайты или --file")

    worst, problems = 0, []
    for t in targets:
        code, line = check_one(t, a.warn_days, a.timeout)
        print(line)
        worst = max(worst, code)
        if code:
            problems.append(line)
    if a.telegram and problems:
        send_telegram("Проверка SSL:\n" + "\n".join(problems))
    sys.exit(worst)


if __name__ == "__main__":
    main()
