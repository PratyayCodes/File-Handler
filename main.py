import os
import io
import json
import zipfile
import base64
import hashlib
import hmac
from datetime import datetime
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

# -----------------------------
# CONFIG
# -----------------------------
SCOPES = ['https://www.googleapis.com/auth/drive.file']
MANIFEST_NAME = "CodePBackupManifest.enc"
TOKEN_FILE = "token.json"
TEMP_DIR = "temp"
BASE36_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

os.makedirs(TEMP_DIR, exist_ok=True)

# -----------------------------
# CRYPTO FUNCTIONS
# -----------------------------
def derive_key(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,  # increased iterations
    )
    key = kdf.derive(password.encode())
    return key, salt


def encrypt_data(data: bytes, password: str):
    key, salt = derive_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + encrypted


def decrypt_data(enc_data: bytes, password: str):
    salt = enc_data[:16]
    nonce = enc_data[16:28]
    ciphertext = enc_data[28:]
    key, _ = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# -----------------------------
# FILENAME ENCRYPTION
# -----------------------------
def encrypt_filename(filename: str, password: str) -> str:
    key = hashlib.sha256(password.encode()).digest()
    digest = hmac.new(key, filename.encode(), hashlib.sha256).digest()
    number = int.from_bytes(digest, 'big')
    base36 = ''
    while number > 0:
        number, rem = divmod(number, 36)
        base36 = BASE36_CHARS[rem] + base36
    return (base36 or "0")[:32] + ".enc"


# -----------------------------
# ZIP FUNCTIONS
# -----------------------------
def zip_folder(folder_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, folder_path)
                zipf.write(abs_path, rel_path)


def unzip_file(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)


# -----------------------------
# GOOGLE DRIVE FUNCTIONS
# -----------------------------
def authenticate_drive():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
    return build('drive', 'v3', credentials=creds)


def upload_to_drive(service, file_path, drive_name):
    with open(file_path, 'rb') as f:
        media = MediaIoBaseUpload(f, mimetype='application/octet-stream', resumable=True)
        file_metadata = {'name': drive_name}
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    return file.get('id')


def download_from_drive(service, drive_name):
    results = service.files().list(q=f"name='{drive_name}'", fields="files(id, name)").execute()
    items = results.get('files', [])
    if not items:
        return None
    file_id = items[0]['id']
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, service.files().get_media(fileId=file_id))
    done = False
    while not done:
        _, done = downloader.next_chunk()
    fh.seek(0)
    return fh.read()


# -----------------------------
# MANIFEST FUNCTIONS
# -----------------------------

def load_manifest(service, password):
    """
    Downloads and decrypts the manifest from Google Drive.
    Returns {"files": []} if no manifest exists.
    """
    enc_data = download_from_drive(service, MANIFEST_NAME)
    if not enc_data:
        return {"files": []}
    data = decrypt_data(enc_data, password)
    return json.loads(data.decode('utf-8'))


def save_manifest(service, manifest, password):
    """
    Saves the manifest to Google Drive.
    If a manifest already exists, it updates the existing file instead of creating a new one.
    """
    # Convert manifest to JSON bytes and encrypt
    data = json.dumps(manifest).encode('utf-8')
    enc_data = encrypt_data(data, password)

    # Save to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR) as tmp:
        tmp.write(enc_data)
        tmp_path = tmp.name

    media = MediaIoBaseUpload(io.FileIO(tmp_path, 'rb'), mimetype='application/octet-stream')

    # Check if manifest already exists
    existing = service.files().list(q=f"name='{MANIFEST_NAME}'", fields="files(id)").execute()
    files = existing.get('files', [])

    if files:
        # Manifest exists → update it
        file_id = files[0]['id']
        service.files().update(fileId=file_id, media_body=media).execute()
    else:
        # Manifest does not exist → create new
        file_metadata = {'name': MANIFEST_NAME}
        service.files().create(body=file_metadata, media_body=media, fields='id').execute()

    # Clean up temporary file
    os.remove(tmp_path)


def add_file_to_manifest(manifest, original_name, encrypted_name, size, type="file", contents=None):
    """
    Adds a file or folder entry to the manifest.
    """
    entry = {
        "type": type,
        "original_name": original_name,
        "encrypted_name": encrypted_name,
        "size": size
    }
    if contents:
        entry["contents"] = contents
    manifest["files"].append(entry)

# -----------------------------
# FOLDER PROCESSING
# -----------------------------
def process_folder_contents(folder_path):
    def walk_dir(path):
        items = []
        for entry in os.scandir(path):
            if entry.is_file():
                items.append({"type": "file", "name": os.path.relpath(entry.path, folder_path), "size": entry.stat().st_size})
            elif entry.is_dir():
                items.append({"type": "folder", "name": os.path.relpath(entry.path, folder_path), "contents": walk_dir(entry.path)})
        return items
    return walk_dir(folder_path)


# -----------------------------
# CLI FUNCTIONS
# -----------------------------
def upload_file(service, password, manifest):
    file_path = input("File path: ").strip()
    if not os.path.isfile(file_path):
        print("File does not exist.")
        return
    encrypted_name = encrypt_filename(os.path.basename(file_path), password)
    with open(file_path, 'rb') as f:
        data = encrypt_data(f.read(), password)
    with tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    upload_to_drive(service, tmp_path, encrypted_name)
    add_file_to_manifest(manifest, os.path.basename(file_path), encrypted_name, os.path.getsize(file_path))
    save_manifest(service, manifest, password)
    os.remove(tmp_path)
    print("File uploaded successfully.")


def upload_folder(service, password, manifest):
    folder_path = input("Folder path: ").strip()
    if not os.path.isdir(folder_path):
        print("Folder does not exist.")
        return
    with tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR, suffix=".zip") as tmp_zip:
        zip_folder(folder_path, tmp_zip.name)
        zip_data = encrypt_data(open(tmp_zip.name, 'rb').read(), password)
    with tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR) as tmp_enc:
        tmp_enc.write(zip_data)
        enc_path = tmp_enc.name
    encrypted_name = encrypt_filename(os.path.basename(folder_path), password)
    upload_to_drive(service, enc_path, encrypted_name)
    folder_contents = process_folder_contents(folder_path)
    add_file_to_manifest(manifest, os.path.basename(folder_path), encrypted_name,
                         os.path.getsize(tmp_zip.name), type="folder", contents=folder_contents)
    save_manifest(service, manifest, password)
    os.remove(tmp_zip.name)
    os.remove(enc_path)
    print("Folder uploaded successfully.")


def download_item(service, password, manifest):
    if not manifest["files"]:
        print("No files to download.")
        return
    print("Available backups:")
    for idx, f in enumerate(manifest["files"]):
        print(f"{idx}: {f['original_name']} ({f['type']})")
    try:
        choice = int(input("Select file/folder index to download: "))
    except ValueError:
        print("Invalid input.")
        return
    if choice < 0 or choice >= len(manifest["files"]):
        print("Invalid selection.")
        return
    item = manifest["files"][choice]
    enc_data = download_from_drive(service, item['encrypted_name'])
    if not enc_data:
        print("File not found on Drive.")
        return
    data = decrypt_data(enc_data, password)
    if item["type"] == "file":
        with open(item['original_name'], 'wb') as f:
            f.write(data)
        print(f"File {item['original_name']} downloaded and decrypted.")
    elif item["type"] == "folder":
        with tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR, suffix=".zip") as tmp_zip:
            tmp_zip.write(data)
            tmp_zip_path = tmp_zip.name
        unzip_file(tmp_zip_path, item['original_name'])
        os.remove(tmp_zip_path)
        print(f"Folder {item['original_name']} downloaded and decrypted.")




def interactive_glance_mode(service, manifest, password):
    """
    Fully upgraded interactive Glance Mode:
    - Expand/collapse folders
    - Filter by type (file/folder)
    - Download files/folders
    - Delete files/folders safely
    """
    from copy import deepcopy

    expanded = set()
    current_filter = None  # None, 'file', or 'folder'

    # Flatten manifest for interactive indexing
    def flatten(files, parent_path=""):
        flat_list = []
        for f in files:
            path = f"{parent_path}/{f.get('original_name') or f.get('name')}"
            flat_list.append((path, f))
            if f["type"] == "folder" and path in expanded:
                flat_list.extend(flatten(f.get("contents", []), path))
        return flat_list

    def human_readable_size(size):
        for unit in ["bytes", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    def print_list():
        flat = flatten(manifest["files"])
        indexed = []
        print("\n=== Interactive Glance Mode ===")
        print("Commands: o <index> = open, c <index> = collapse, f <file/folder/all> = filter, d <index> = download, x <index> = delete, q = quit")
        for i, (path, f) in enumerate(flat):
            if current_filter and f["type"] != current_filter:
                continue
            indent = "  " * path.count("/")
            icon = "📁" if f["type"] == "folder" else "📄"
            size = human_readable_size(f.get("size", 0))
            items_info = f", {len(f.get('contents', []))} items" if f["type"] == "folder" else ""
            print(f"{i}: {indent}{icon} {f.get('original_name') or f.get('name')} ({size}{items_info})")
            indexed.append((i, path, f))
        return indexed

    while True:
        indexed = print_list()
        cmd = input("\nCommand: ").strip()
        if cmd.lower() == "q":
            break
        elif cmd.startswith("o "):
            try:
                idx = int(cmd[2:])
                _, path, f = indexed[idx]
                if f["type"] == "folder":
                    expanded.add(path)
            except:
                print("Invalid index")
        elif cmd.startswith("c "):
            try:
                idx = int(cmd[2:])
                _, path, f = indexed[idx]
                if f["type"] == "folder" and path in expanded:
                    expanded.remove(path)
            except:
                print("Invalid index")
        elif cmd.startswith("f "):
            arg = cmd[2:].strip().lower()
            if arg in ["file", "folder"]:
                current_filter = arg
            elif arg == "all":
                current_filter = None
            else:
                print("Invalid filter type")
        elif cmd.startswith("d "):
            try:
                idx = int(cmd[2:])
                _, _, f = indexed[idx]
                print(f"Downloading {f.get('original_name') or f.get('name')}...")
                download_item_from_manifest(service, password, f)
            except:
                print("Invalid index")
        elif cmd.startswith("x "):
            try:
                idx = int(cmd[2:])
                _, _, f = indexed[idx]
                name_to_delete = f.get('original_name') or f.get('name')
                confirm = input(f"Are you sure you want to delete '{name_to_delete}'? (y/n): ").lower()
                if confirm == "y":
                    delete_item_from_drive(service, f)
                    # Remove from manifest
                    remove_item_from_manifest(manifest, f)
                    save_manifest(service, manifest, password)
                    print(f"'{name_to_delete}' deleted successfully.")
            except:
                print("Invalid index or deletion failed")
        else:
            print("Unknown command")


def download_item_from_manifest(service, password, item):
    """Downloads a file or folder given a manifest entry"""
    enc_data = download_from_drive(service, item['encrypted_name'])
    if not enc_data:
        print("File not found on Drive.")
        return
    data = decrypt_data(enc_data, password)
    if item["type"] == "file":
        with open(item['original_name'] or item['name'], 'wb') as f:
            f.write(data)
        print(f"File {item['original_name'] or item['name']} downloaded.")
    elif item["type"] == "folder":
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
            tmp_zip.write(data)
            zip_path = tmp_zip.name
        unzip_file(zip_path, item['original_name'] or item['name'])
        os.remove(zip_path)
        print(f"Folder {item['original_name'] or item['name']} downloaded.")


def delete_item_from_drive(service, item):
    """Deletes a file/folder from Google Drive by looking up its file ID"""
    results = service.files().list(q=f"name='{item['encrypted_name']}'", fields="files(id)").execute()
    files = results.get("files", [])
    if not files:
        print("File not found on Drive for deletion.")
        return
    file_id = files[0]["id"]
    service.files().delete(fileId=file_id).execute()


def remove_item_from_manifest(manifest, item):
    """Recursively remove an item from the manifest"""
    def recurse_remove(files, target):
        for f in files:
            if f == target:
                files.remove(f)
                return True
            if f["type"] == "folder" and recurse_remove(f.get("contents", []), target):
                return True
        return False

    recurse_remove(manifest["files"], item)
# -----------------------------
# MAIN CLI LOOP
# -----------------------------
def main():
    print("""
    
$$$$$$\                  $$\           $$$$$$$\        $$$$$$$\  $$$$$$$\  
$$  __$$\                 $$ |          $$  __$$\       $$  __$$\ $$  __$$\ 
$$ /  \__| $$$$$$\   $$$$$$$ | $$$$$$\  $$ |  $$ |      $$ |  $$ |$$ |  $$ |
$$ |      $$  __$$\ $$  __$$ |$$  __$$\ $$$$$$$  |      $$ |  $$ |$$$$$$$\ |
$$ |      $$ /  $$ |$$ /  $$ |$$$$$$$$ |$$  ____/       $$ |  $$ |$$  __$$\ 
$$ |  $$\ $$ |  $$ |$$ |  $$ |$$   ____|$$ |            $$ |  $$ |$$ |  $$ |
\$$$$$$  |\$$$$$$  |\$$$$$$$ |\$$$$$$$\ $$ |            $$$$$$$  |$$$$$$$  |
 \______/  \______/  \_______| \_______|\__|            \_______/ \_______/ 
                                                                            

    
    
          """)
    service = authenticate_drive()
    password = input("Enter your encryption password: ")
    manifest = load_manifest(service, password)

    while True:
        mode = input("\nMode: (u=upload, d=download, g=glance, q=quit): ").lower()
        if mode == 'u':
            type_choice = input("Upload (f=file, o=folder): ").lower()
            if type_choice == 'f':
                upload_file(service, password, manifest)
            elif type_choice == 'o':
                upload_folder(service, password, manifest)
            else:
                print("Invalid choice.")
        elif mode == 'd':
            download_item(service, password, manifest)
        elif mode == 'g':
            interactive_glance_mode(service, manifest, password)
        elif mode == 'q':
            print("Exiting...")
            break
        else:
            print("Invalid mode.")


if __name__ == "__main__":
    main()
