import os
import io
import json
import zipfile
import base64
import hashlib
import hmac
from datetime import datetime

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
TEMP_DIR = "temp"

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
        iterations=100_000,
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
# FILENAME ENCRYPTION (HMAC + Base36)
# -----------------------------
BASE36_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def encrypt_filename(filename: str, password: str) -> str:
    key = hashlib.sha256(password.encode()).digest()
    digest = hmac.new(key, filename.encode(), hashlib.sha256).digest()
    number = int.from_bytes(digest, 'big')
    base36 = ''
    while number > 0:
        number, rem = divmod(number, 36)
        base36 = BASE36_CHARS[rem] + base36
    return base36[:32] + ".enc"


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
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES)
    creds = flow.run_local_server(port=0)
    service = build('drive', 'v3', credentials=creds)
    return service


def upload_to_drive(service, file_path, drive_name):
    media = MediaIoBaseUpload(io.FileIO(file_path, 'rb'), mimetype='application/octet-stream')
    file_metadata = {'name': drive_name}
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    return file.get('id')


def download_from_drive(service, drive_name):
    results = service.files().list(q=f"name='{drive_name}'").execute()
    items = results.get('files', [])
    if not items:
        return None
    file_id = items[0]['id']
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, service.files().get_media(fileId=file_id))
    done = False
    while not done:
        status, done = downloader.next_chunk()
    fh.seek(0)
    return fh.read()


def list_drive_files(service):
    results = service.files().list().execute()
    return results.get('files', [])


# -----------------------------
# MANIFEST FUNCTIONS
# -----------------------------
def load_manifest(service, password):
    enc_data = download_from_drive(service, MANIFEST_NAME)
    if not enc_data:
        return {"files": []}
    data = decrypt_data(enc_data, password)
    return json.loads(data.decode('utf-8'))


def save_manifest(service, manifest, password):
    data = json.dumps(manifest).encode('utf-8')
    enc_data = encrypt_data(data, password)
    temp_path = os.path.join(TEMP_DIR, "manifest.enc")
    with open(temp_path, 'wb') as f:
        f.write(enc_data)
    upload_to_drive(service, temp_path, MANIFEST_NAME)
    os.remove(temp_path)


def add_file_to_manifest(manifest, original_name, encrypted_name, size, type="file", contents=None):
    entry = {"type": type, "original_name": original_name, "encrypted_name": encrypted_name, "size": size}
    if contents:
        entry["contents"] = contents
    manifest["files"].append(entry)


# -----------------------------
# UTILITY FUNCTIONS
# -----------------------------
def process_folder_contents(folder_path):
    contents = []
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            path = os.path.join(root, f)
            rel = os.path.relpath(path, folder_path)
            size = os.path.getsize(path)
            contents.append({"type": "file", "name": rel, "size": size})
        for d in dirs:
            d_path = os.path.join(root, d)
            rel = os.path.relpath(d_path, folder_path)
            contents.append({"type": "folder", "name": rel, "contents": []})
    return contents


# -----------------------------
# MAIN CLI
# -----------------------------
def main():
    print("=== CodeP Backup ===")
    service = authenticate_drive()
    password = input("Enter your encryption password: ")
    manifest = load_manifest(service, password)

    while True:
        mode = input("\nMode: (u=upload, d=download, g=glance, q=quit): ").lower()
        if mode == 'u':
            type_choice = input("Upload (f=file, o=folder): ").lower()
            if type_choice == 'f':
                file_path = input("File path: ").strip()
                if not os.path.isfile(file_path):
                    print("File does not exist.")
                    continue
                encrypted_name = encrypt_filename(os.path.basename(file_path), password)
                with open(file_path, 'rb') as f:
                    data = f.read()
                temp_path = os.path.join(TEMP_DIR, "temp.enc")
                with open(temp_path, 'wb') as f:
                    f.write(encrypt_data(data, password))
                upload_to_drive(service, temp_path, encrypted_name)
                add_file_to_manifest(manifest, os.path.basename(file_path), encrypted_name, os.path.getsize(file_path))
                save_manifest(service, manifest, password)
                os.remove(temp_path)
                print("File uploaded successfully.")

            elif type_choice == 'o':
                folder_path = input("Folder path: ").strip()
                if not os.path.isdir(folder_path):
                    print("Folder does not exist.")
                    continue
                zip_path = os.path.join(TEMP_DIR, "folder.zip")
                zip_folder(folder_path, zip_path)
                encrypted_name = encrypt_filename(os.path.basename(folder_path), password)
                with open(zip_path, 'rb') as f:
                    data = f.read()
                temp_path = os.path.join(TEMP_DIR, "temp.enc")
                with open(temp_path, 'wb') as f:
                    f.write(encrypt_data(data, password))
                upload_to_drive(service, temp_path, encrypted_name)
                folder_contents = process_folder_contents(folder_path)
                add_file_to_manifest(manifest, os.path.basename(folder_path), encrypted_name,
                                     os.path.getsize(zip_path), type="folder", contents=folder_contents)
                save_manifest(service, manifest, password)
                os.remove(zip_path)
                os.remove(temp_path)
                print("Folder uploaded successfully.")
            else:
                print("Invalid choice.")

        elif mode == 'd':
            if not manifest["files"]:
                print("No files to download.")
                continue
            print("Available backups:")
            for idx, f in enumerate(manifest["files"]):
                print(f"{idx}: {f['original_name']} ({f['type']})")
            choice = int(input("Select file/folder index to download: "))
            if choice < 0 or choice >= len(manifest["files"]):
                print("Invalid selection.")
                continue
            item = manifest["files"][choice]
            enc_data = download_from_drive(service, item['encrypted_name'])
            if not enc_data:
                print("File not found on Drive.")
                continue
            data = decrypt_data(enc_data, password)
            if item["type"] == "file":
                with open(item['original_name'], 'wb') as f:
                    f.write(data)
                print(f"File {item['original_name']} downloaded and decrypted.")
            elif item["type"] == "folder":
                zip_path = os.path.join(TEMP_DIR, "folder_download.zip")
                with open(zip_path, 'wb') as f:
                    f.write(data)
                unzip_file(zip_path, item['original_name'])
                os.remove(zip_path)
                print(f"Folder {item['original_name']} downloaded and decrypted.")

        elif mode == 'g':
            if not manifest["files"]:
                print("No backups available.")
                continue
            print("\n=== Glance Mode ===")
            def print_contents(files, prefix=""):
                for f in files:
                    print(f"{prefix}- {f['original_name']} ({f['type']}, {f['size']} bytes)")
                    if f['type'] == 'folder' and "contents" in f:
                        print_contents(f["contents"], prefix + "  ")
            print_contents(manifest["files"])

        elif mode == 'q':
            print("Exiting...")
            break
        else:
            print("Invalid mode.")


if __name__ == "__main__":
    main()
