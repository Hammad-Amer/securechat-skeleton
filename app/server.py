# server.py 
"""
Refactored server for securechat-skeleton.

Behavior:
 - Accepts TCP connections on HOST:PORT
 - Exchanges certificates with client and performs mutual verification
 - Performs an ephemeral DH exchange for the control plane (login/register)
 - Uses a separate DH exchange for the session (chat) key
 - Handles register/login requests against MariaDB (using DB_CONFIG)
 - Receives signed, encrypted chat messages and echoes/logs them
 - Produces a signed transcript receipt at session close
"""
import socket
import json
import traceback
import mysql.connector
import datetime
from pathlib import Path

# crypto helpers & config (same modules as before)
import security_utils as sec
from config import DB_CONFIG
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HOST = "localhost"
PORT = 65432

# ---------------------------
# Database helpers
# ---------------------------
def get_db_connection():
    """Open and return a MariaDB connection (or None on failure)."""
    try:
        cn = mysql.connector.connect(**DB_CONFIG)
        print("DB: connected")
        return cn
    except mysql.connector.Error as e:
        print(f"DB ERROR: {e}")
        return None


def db_register_user(email: str, username: str, salt: bytes, pwd_hash: str):
    """
    Insert a new user row. Returns (ok:bool, message:str).
    salt is stored as VARBINARY.
    """
    cn = get_db_connection()
    if cn is None:
        return False, "Database connection failed."
    try:
        cur = cn.cursor()
        cur.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        cn.commit()
        return True, "Registration successful."
    except mysql.connector.Error as err:
        if err.errno == 1062:
            return False, "Email or username already exists."
        return False, f"Database error: {err}"
    finally:
        try:
            cur.close()
            cn.close()
        except Exception:
            pass


def db_fetch_user_by_email(email: str):
    """
    Return dict with keys salt,pwd_hash,username or None if not found.
    """
    cn = get_db_connection()
    if cn is None:
        return None, "Database connection failed."
    try:
        cur = cn.cursor(dictionary=True)
        cur.execute("SELECT salt, pwd_hash, username FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        return row, None
    except mysql.connector.Error as err:
        return None, f"Database error: {err}"
    finally:
        try:
            cur.close()
            cn.close()
        except Exception:
            pass


def db_get_salt_hex(email: str):
    cn = get_db_connection()
    if cn is None:
        return None, "Database connection failed."
    try:
        cur = cn.cursor(dictionary=True)
        cur.execute("SELECT salt FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        if row:
            return row["salt"].hex(), None
        # return ok no salt to avoid enumeration
        return None, None
    except mysql.connector.Error as err:
        return None, f"Database error: {err}"
    finally:
        try:
            cur.close()
            cn.close()
        except Exception:
            pass


# ---------------------------
# Per-client handling
# ---------------------------
def handle_client(conn: socket.socket, addr):
    """
    Process one client connection from handshake -> auth -> session -> receipt.
    """
    peer_ip, peer_port = addr[0], addr[1]
    session_transcript = Path(f"server_transcript_{peer_ip}_{peer_port}.log")
    transcript_fp = session_transcript.open("a", encoding="utf-8")

    def log(line: str):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(line)
        transcript_fp.write(f"{ts} | {line}\n")
        transcript_fp.flush()

    log(f"Connection from {addr} established")

    # Local placeholders
    server_cert = None
    server_privkey = None
    client_cert = None
    session_key = None

    try:
        # --- load server materials ---
        log("Loading server certificate / key / CA certificate")
        server_cert = sec.load_cert("server")
        server_privkey = sec.load_private_key("server")
        ca_cert = sec.load_ca_cert()

        # --- certificate exchange ---
        log("Sending server certificate to client")
        conn.sendall(server_cert.public_bytes(serialization.Encoding.PEM))

        log("Receiving client certificate")
        raw_client_cert = conn.recv(8192)
        if not raw_client_cert:
            raise ConnectionError("Client disconnected before sending cert")
        client_cert = x509.load_pem_x509_certificate(raw_client_cert, backend=default_backend())

        # --- verify client cert ---
        log("Verifying client certificate against CA")
        if not sec.verify_peer_cert(client_cert, ca_cert, "client.user"):
            raise Exception("Client certificate verification failed")
        log("Client certificate verified")

        # --- ephemeral DH for control plane (login/registration) ---
        log("Performing ephemeral DH for control plane")
        ctrl_priv, ctrl_pub = sec.dh_generate_keys()
        conn.sendall(ctrl_pub)
        peer_ctrl_pub = conn.recv(8192)
        if not peer_ctrl_pub:
            raise ConnectionError("Client disconnected during control DH")
        ctrl_shared = sec.dh_derive_shared_secret(ctrl_priv, peer_ctrl_pub)
        ctrl_aes_key = sec.derive_key_from_dh_secret(ctrl_shared)
        log("Control plane AES key derived")

        # --- authentication loop (encrypted with ctrl key) ---
        username_for_session = None
        while True:
            enc_req = conn.recv(8192)
            if not enc_req:
                raise ConnectionError("Client disconnected during auth phase")

            req_json = sec.decrypt_aes_cbc(ctrl_aes_key, enc_req)
            if req_json is None:
                log("Failed to decrypt auth request. Terminating session.")
                return

            try:
                req = json.loads(req_json.decode("utf-8"))
            except Exception:
                log("Malformed JSON in auth request")
                return

            log(f"Auth command received: {req.get('type')}")
            resp = {"status": "error", "message": "Unhandled command"}

            if req.get("type") == "register":
                ok, msg = db_register_user(req["email"], req["username"], bytes.fromhex(req["salt_hex"]), req["pwd_hash"])
                resp = {"status": "ok" if ok else "error", "message": msg}
            elif req.get("type") == "login_request":
                salt_hex, db_err = db_get_salt_hex(req["email"])
                if db_err:
                    resp = {"status": "error", "message": db_err}
                else:
                    resp = {"status": "ok", "salt_hex": salt_hex}
            elif req.get("type") == "login":
                user_row, db_err = db_fetch_user_by_email(req["email"])
                if db_err:
                    resp = {"status": "error", "message": db_err}
                elif not user_row:
                    resp = {"status": "error", "message": "Invalid email or password."}
                else:
                    # client already sent pwd_hash computed as SHA256(salt || password)
                    if req["pwd_hash"] == user_row["pwd_hash"]:
                        resp = {"status": "ok", "message": "Login successful.", "username": user_row["username"]}
                        username_for_session = user_row["username"]
                    else:
                        resp = {"status": "error", "message": "Invalid email or password."}
            else:
                resp = {"status": "error", "message": "Unknown command"}

            # send response (encrypted with control key)
            resp_b = json.dumps(resp).encode("utf-8")
            conn.sendall(sec.encrypt_aes_cbc(ctrl_aes_key, resp_b))

            if req.get("type") == "login" and resp.get("status") == "ok":
                log("Authentication completed successfully; proceeding to session key exchange")
                break

        # --- session DH (separate ephemeral keys) ---
        log("Performing session DH exchange")
        sess_priv, sess_pub = sec.dh_generate_keys()
        conn.sendall(sess_pub)
        peer_sess_pub = conn.recv(8192)
        if not peer_sess_pub:
            raise ConnectionError("Client disconnected during session DH")
        sess_shared = sec.dh_derive_shared_secret(sess_priv, peer_sess_pub)
        session_key = sec.derive_key_from_dh_secret(sess_shared)
        log("Session AES key established")

        # --- data plane (chat) ---
        log("Entering data plane (secure chat) — waiting for messages")
        seq_expected = 0
        client_pubkey = client_cert.public_key()

        while True:
            enc_msg = conn.recv(8192)
            if not enc_msg:
                log("Client disconnected from data plane")
                break

            # decrypt with session key
            msg_json = sec.decrypt_aes_cbc(session_key, enc_msg)
            if msg_json is None:
                log("Failed to decrypt incoming message — skipping")
                continue

            try:
                payload = json.loads(msg_json.decode("utf-8"))
            except Exception:
                log("Invalid JSON message — skipping")
                continue

            mtype = payload.get("type")
            if mtype == "logout":
                log(f"Client {username_for_session or '<unknown>'} requested logout")
                break

            # expected fields: seqno, ts, ct_hex, sig_hex
            seqno = payload.get("seqno", -1)
            ts = payload.get("ts", "")
            ct_hex = payload.get("ct_hex", "")
            sig_hex = payload.get("sig_hex", "")

            # replay protection
            if not isinstance(seqno, int) or seqno <= seq_expected:
                log(f"Replay or bad seqno: got {seqno}, expected > {seq_expected} — ignoring")
                continue
            seq_expected = seqno

            try:
                ct_bytes = bytes.fromhex(ct_hex)
            except Exception:
                log("Bad ciphertext hex — ignoring message")
                continue

            # construct digest that client signed: SHA256(seqno || ts || ciphertext)
            signed_payload = f"{seqno}{ts}".encode("utf-8") + ct_bytes
            digest = sec.hash_sha256(signed_payload)

            # verify signature
            try:
                sig_bytes = bytes.fromhex(sig_hex)
            except Exception:
                log("Bad signature hex — ignoring message")
                continue

            if not sec.verify_signature(client_pubkey, sig_bytes, digest):
                log("Signature verification failed — ignoring message")
                continue

            # decrypt inner ciphertext with session key
            plaintext = sec.decrypt_aes_cbc(session_key, ct_bytes)
            if plaintext is None:
                log("Inner ciphertext decryption failed — ignoring")
                continue

            # message is valid
            log(f"[{username_for_session or 'client'}] {plaintext.decode('utf-8', errors='replace')}")

            # simple echo behavior: server does not send a chat reply in this assignment

    except ConnectionResetError:
        log(f"ConnectionResetError from {addr}")
    except Exception as exc:
        log(f"Unhandled exception: {exc}")
        traceback.print_exc()
    finally:
        try:
            # produce signed transcript receipt
            transcript_fp.close()
            transcript_bytes = session_transcript.read_bytes() if session_transcript.exists() else b""
            transcript_digest = sec.hash_sha256(transcript_bytes)
            signature = sec.sign(server_privkey, transcript_digest) if server_privkey else b""

            receipt = {
                "type": "SessionReceipt",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8") if server_cert else None,
                "client_cert": client_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8") if client_cert else None,
                "transcript_hash_hex": transcript_digest.hex(),
                "signature_hex": signature.hex()
            }

            receipt_path = Path(f"server_receipt_{peer_ip}_{peer_port}.json")
            receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            log(f"Saved receipt to {receipt_path}")

            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            conn.close()
            log(f"Closed connection to {addr}")
        except Exception as e:
            print("Error during cleanup:", e)


# ---------------------------
# Main server loop
# ---------------------------
def main():
    """
    Entry point for the secure chat server.
    Responsible for:
      - Ensuring DB connectivity
      - Binding and listening on the TCP port
      - Accepting incoming client connections
      - Handing each client to handle_client() for full protocol flow
    """

    # Before starting the server, verify that the database is reachable.
    # This prevents the server from running in a half-broken state.
    test_conn = get_db_connection()
    if not test_conn:
        print("CRITICAL: DB unavailable — aborting server start.")
        return
    test_conn.close()

    # Create a TCP socket and configure it for incoming clients.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        # Allow immediate reuse of the port after restarting the server.
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the server to HOST:PORT.
        srv.bind((HOST, PORT))

        # Start listening for connection requests.
        # '5' is the backlog (max queued pending connections).
        srv.listen(5)
        print(f"Server listening on {HOST}:{PORT}")

        try:
            # Main loop — accept clients one at a time.
            # (The assignment requires a single-threaded flow;
            #  a real server would spawn a thread per client.)
            while True:
                client_sock, client_addr = srv.accept()

                # Pass the connection to the handler that performs:
                # - certificate exchange
                # - DH key exchange
                # - authentication
                # - encrypted chat session
                handle_client(client_sock, client_addr)

        except KeyboardInterrupt:
            # Graceful shutdown on Ctrl+C
            print("\nShutting down server.")

        finally:
            # Explicit close for clarity, though context manager handles it.
            srv.close()



if __name__ == "__main__":
    main()
