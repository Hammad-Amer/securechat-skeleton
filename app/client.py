# client.py 
"""
Secure Chat Client —

Performs:
 - Certificate exchange + verification
 - Ephemeral DH (control plane)
 - Secure login/register
 - Ephemeral DH (session)
 - Signed & encrypted chat messages
 - Transcript logging + signed receipt
"""

import socket
import json
import getpass
import threading
import time
import sys
import traceback
import datetime
from pathlib import Path

import security_utils as sec
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HOST = "localhost"
PORT = 65432

# Global flag for message receiving thread
chat_active = threading.Event()


# ============================================================
# Utility helpers
# ============================================================

def _encrypt_and_send(sock, key, payload: dict):
    """Encrypt dict → send → receive response → decrypt → dict."""
    raw = json.dumps(payload).encode("utf-8")
    encrypted = sec.encrypt_aes_cbc(key, raw)
    sock.sendall(encrypted)

    resp = sock.recv(4096)
    if not resp:
        raise ConnectionError("Server disconnected during command exchange.")

    decrypted = sec.decrypt_aes_cbc(key, resp)
    if decrypted is None:
        raise Exception("Could not decrypt server reply")

    return json.loads(decrypted.decode("utf-8"))


def log_line(fh, text):
    """Write timestamped log entry to transcript."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    fh.write(f"{ts} | {text}\n")
    fh.flush()


# ============================================================
# Background receive loop (rarely used but required by structure)
# ============================================================

def receiver_thread(sock, key, server_pub, transcript):
    """
    Background thread responsible for passively listening for any
    incoming messages from the server during the chat phase.

    In this assignment, the server does not actively push messages
    to the client, but a real chat system would use this thread to
    receive incoming chat messages from other users or system events.
    """
    try:
        # A timeout is used so the loop can periodically check whether
        # chat_active flag is still set. Without this, recv() would block forever.
        sock.settimeout(1.0)

        while chat_active.is_set():
            try:
                # Non-blocking wait for server messages.
                packet = sock.recv(4096)

                # If recv() returns empty data, it means the server closed the connection.
                if not packet:
                    print("\n[Server disconnected.]")
                    chat_active.clear()
                    break

                # NOTE:
                # In the actual assignment, the server does not send messages during chat.
                # If it did, this is where we would decrypt, verify, and display them.

            except socket.timeout:
                # Normal case: no data received during timeout window.
                # Loop again to re-check chat_active flag.
                continue

            except Exception as exc:
                # Any other exception means a network error.
                if chat_active.is_set():
                    print(f"[Receiver error: {exc}]")
                    chat_active.clear()
                break

    finally:
        # Remove timeout before thread exits to restore normal socket behavior.
        sock.settimeout(None)



# ============================================================
# Main Client Procedure
# ============================================================

def main():
    client_cert = None
    client_key = None
    server_cert = None

    transcript_path = Path("client_transcript.log")

    with transcript_path.open("a", encoding="utf-8") as transcript:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect((HOST, PORT))
                log_line(transcript, f"Connected to {HOST}:{PORT}")

                # ------------------------------------
                # Load credentials
                # ------------------------------------
                log_line(transcript, "Loading local credentials (client + CA)")
                client_cert = sec.load_cert("client")
                client_key = sec.load_private_key("client")
                ca_cert = sec.load_ca_cert()

                # ------------------------------------
                # Certificate exchange
                # ------------------------------------
                log_line(transcript, "Receiving server certificate")
                server_bytes = sock.recv(4096)
                if not server_bytes:
                    raise ConnectionError("Server disconnected (no certificate).")

                server_cert = x509.load_pem_x509_certificate(server_bytes, backend=default_backend())

                # Verify server
                if not sec.verify_peer_cert(server_cert, ca_cert, "localhost"):
                    raise Exception("Server certificate verification failed")

                log_line(transcript, "Server certificate verified")
                log_line(transcript, "Sending client certificate")
                sock.sendall(client_cert.public_bytes(serialization.Encoding.PEM))

                # ------------------------------------
                # Ephemeral DH (control plane)
                # ------------------------------------
                log_line(transcript, "Starting control-plane DH handshake")
                srv_ephemeral_pub = sock.recv(4096)
                if not srv_ephemeral_pub:
                    raise ConnectionError("Server disconnected during DH exchange")

                cli_priv, cli_pub = sec.dh_generate_keys()
                sock.sendall(cli_pub)

                shared_tmp = sec.dh_derive_shared_secret(cli_priv, srv_ephemeral_pub)
                ctrl_key = sec.derive_key_from_dh_secret(shared_tmp)

                log_line(transcript, "Temporary AES key established")

                # ------------------------------------
                # Login / Register phase (encrypted)
                # ------------------------------------
                while True:
                    print("\n=== Secure Access ===")
                    action = input("register / login: ").strip().lower()

                    if action == "register":
                        email = input("Email: ").strip()
                        username = input("Username: ").strip()
                        password = getpass.getpass("Password: ")

                        salt = sec.generate_salt()
                        hashed = sec.hash_password(password, salt)

                        req = {
                            "type": "register",
                            "email": email,
                            "username": username,
                            "salt_hex": salt.hex(),
                            "pwd_hash": hashed
                        }

                        resp = _encrypt_and_send(sock, ctrl_key, req)
                        print("Server:", resp.get("message"))

                    elif action == "login":
                        email = input("Email: ").strip()
                        password = getpass.getpass("Password: ")

                        # request salt
                        salt_req = {"type": "login_request", "email": email}
                        sr = _encrypt_and_send(sock, ctrl_key, salt_req)

                        if sr["status"] != "ok" or sr["salt_hex"] is None:
                            print("Server: Invalid email or password.")
                            continue

                        salt = bytes.fromhex(sr["salt_hex"])
                        hashed = sec.hash_password(password, salt)

                        login_req = {"type": "login", "email": email, "pwd_hash": hashed}
                        resp = _encrypt_and_send(sock, ctrl_key, login_req)

                        print("Server:", resp.get("message"))
                        if resp.get("status") == "ok":
                            log_line(transcript, "Login successful")
                            break

                    else:
                        print("Invalid option.")

                # ------------------------------------
                # Session DH exchange
                # ------------------------------------
                log_line(transcript, "Beginning session DH exchange")

                srv_session_pub = sock.recv(4096)
                if not srv_session_pub:
                    raise ConnectionError("Server disconnected during session DH")

                cli_sess_priv, cli_sess_pub = sec.dh_generate_keys()
                sock.sendall(cli_sess_pub)

                shared_sess = sec.dh_derive_shared_secret(cli_sess_priv, srv_session_pub)
                session_key = sec.derive_key_from_dh_secret(shared_sess)

                log_line(transcript, "Session AES key generated")

                # ------------------------------------
                # Chat Mode
                # ------------------------------------
                print("\n=== Secure Chat ===")
                print("Type messages; type 'logout' to exit.")

                chat_active.set()

                # Start background receiver thread
                rcv = threading.Thread(
                    target=receiver_thread,
                    args=(sock, session_key, server_cert.public_key(), transcript),
                    daemon=True
                )
                rcv.start()

                seq_counter = 0

                while chat_active.is_set():
                    msg_text = input()
                    if not chat_active.is_set():
                        break

                    if msg_text.strip().lower() == "logout":
                        logout_obj = {"type": "logout"}
                        encrypted = sec.encrypt_aes_cbc(session_key, json.dumps(logout_obj).encode())
                        sock.sendall(encrypted)

                        log_line(transcript, "Sent logout")
                        chat_active.clear()
                        break

                    # Build signed message
                    seq_counter += 1
                    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

                    inner_ct = sec.encrypt_aes_cbc(session_key, msg_text.encode("utf-8"))

                    data_for_sig = f"{seq_counter}{ts}".encode("utf-8") + inner_ct
                    digest = sec.hash_sha256(data_for_sig)

                    signature = sec.sign(client_key, digest)

                    outer_msg = {
                        "type": "msg",
                        "seqno": seq_counter,
                        "ts": ts,
                        "ct_hex": inner_ct.hex(),
                        "sig_hex": signature.hex()
                    }

                    encrypted_outer = sec.encrypt_aes_cbc(session_key, json.dumps(outer_msg).encode())
                    sock.sendall(encrypted_outer)
                    log_line(transcript, f"Sent[{seq_counter}]: {msg_text}")

                # wait for background thread
                rcv.join()

            except Exception as e:
                log_line(transcript, f"ERROR: {e}")
                traceback.print_exc()
            finally:
                log_line(transcript, "Disconnected from server")

                # ------------------------------------
                # Final signed session receipt
                # ------------------------------------
                if client_key:
                    transcript_bytes = transcript_path.read_bytes()
                    transcript_hash = sec.hash_sha256(transcript_bytes)

                    receipt_sig = sec.sign(client_key, transcript_hash)

                    receipt = {
                        "type": "SessionReceipt",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "client_cert": client_cert.public_bytes(serialization.Encoding.PEM).decode(),
                        "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode(),
                        "transcript_hash_hex": transcript_hash.hex(),
                        "signature_hex": receipt_sig.hex()
                    }

                    Path("client_receipt.json").write_text(json.dumps(receipt, indent=2))
                    print("Client receipt saved → client_receipt.json")

                sock.close()


if __name__ == "__main__":
    main()
