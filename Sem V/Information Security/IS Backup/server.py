#!/usr/bin/env python3
# server.py
# -----------------------------------------------------------------------------
# Educational, menu-style, generic privacy-preserving COMPUTE SERVER
# for Lab 4–8 style questions (Medical records / Banking / HR / etc.)
#
# * Threaded TCP JSON server
# * Persistent JSON storage (server_state.json)
# * Accepts multi-algorithm client payloads:
#     - AES-256 (content encryption, sent as base64)
#     - RSA-2048 (hybrid key wrap; and multiplicative homomorphism “exponent trick”)
#     - ElGamal (digital signature verification with timestamps)
#     - Paillier (additive homomorphism for searchable keyword hashing)
#
# * Auditor APIs:
#     - Search by department keyword via Paillier (privacy-preserving)
#     - Aggregate encrypted expenses via RSA (homomorphic multiplication)
#     - Verify report authenticity and timestamps (ElGamal)
#
# PROTOCOL (all JSON, one line per request/response):
#   Client --> Server:
#     { "op": "...", <op-specific fields> }
#   Server --> Client:
#     { "ok": true/false, "data": ..., "err": "..." }
#
# -----------------------------------------------------------------------------
# DEPENDENCIES: pycryptodome
#   pip install pycryptodome
# -----------------------------------------------------------------------------

import os
import json
import base64
import socket
import threading
import traceback
from datetime import datetime

# ------------------------------
# Storage & Thread Safety
# ------------------------------
STATE_FILE = "server_state.json"
STATE_LOCK = threading.RLock()

"""
State schema (persisted):

{
  "meta": {
     "record_type": "medical"               # can be changed to "banking", etc.
  },
  "keys": {
     # (Optional) Registry for shared/aggregation keys (RSA accumulator)
     "rsa_accumulator": {
         "n": <int>, "e": <int>, "g": <int>   # public parameters for homomorphic expenses
     },
     # (Optional) Auditor's Paillier public key to support searchable equality
     "paillier_pub": {
         "n": <int>, "g": <int>
     }
  },
  "doctors": {
    "doc_username": {
      "registered_at": "2025-10-29 10:30:00",
      "pubkeys": {
         "rsa": {"n": <int>, "e": <int>},
         "elgamal": {"p": <int>, "g": <int>, "y": <int>},
         "paillier": {"n": <int>, "g": <int>}   # optional if doctor holds same auditor pub
      },
      "dept_hash_enc": "base64-Enc_paillier(hash(dept))",   # encrypted dept-hash (Paillier)
      "records": [
         {
           "timestamp": "2025-10-29 10:45:00",
           "aes_ct_b64": "...",      # IV||CT base64 (AES-256-CBC recommended on client)
           "aes_key_rsa_b64": "...", # AES key wrapped with RSA public key(s)
           "sig_scheme": "ElGamal",
           "sig": {"r": <int>, "s": <int>},      # ElGamal signature over H(report||ts)
           "sig_hash_alg": "SHA-256"
         }
      ],
      "expenses": [
         {
           "ts": "2025-10-29 11:00:00",
           "cipher_rsa": { "c": <int> }          # RSA-based homomorphic ciphertext
         }
      ]
    }
  }
}
"""

# -----------------------------------------------------------------------------
# Utilities: Load / Save State (thread-safe)
# -----------------------------------------------------------------------------
def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            "meta": {"record_type": "medical"},
            "keys": {},
            "doctors": {}
        }
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)

# -----------------------------------------------------------------------------
# Minimal Crypto Helpers (Server-side verification / homomorphic ops only)
# NOTE: Server does NOT decrypt AES content; it verifies signatures,
#       applies Paillier/RSA homomorphic operations, and returns results.
# -----------------------------------------------------------------------------

# --- ElGamal signature verification over a hash integer modulo p-1
#     Public key: (p, g, y)
#     Signature: (r, s)
#     Verify: y^r * r^s ≡ g^H (mod p)
#     (Here H is an integer derived from a hash digest)
def elgamal_verify(pub, h_int, sig):
    """
    pub: {p,g,y} ints
    h_int: int (hash digest mapped to integer mod p-1)
    sig: {r,s}
    returns True/False
    """
    p = int(pub["p"]); g = int(pub["g"]); y = int(pub["y"])
    r = int(sig["r"]); s = int(sig["s"])
    if not (1 < r < p):
        return False
    # Check: (y^r * r^s) % p == (g^h) % p
    left = (pow(y, r, p) * pow(r, s, p)) % p
    right = pow(g, h_int, p)
    return left == right

# --- Simple integer hash -> int mapper (from a hex SHA-256 string)
def hexhash_to_int(hex_str, modulus=None):
    x = int(hex_str, 16)
    if modulus:
        return x % modulus
    return x

# --- Paillier homomorphic helpers (server only needs addition on ciphertext)
# Enc(a) * Enc(b) ≡ Enc(a+b) mod n^2
# Also Enc(a) * Enc(-b) ≡ Enc(a-b)
def paillier_mul(c1, c2, n):
    """Multiply two Paillier ciphertexts modulo n^2."""
    n2 = n * n
    return (c1 * c2) % n2

def paillier_pow(c, k, n):
    """Raise a Paillier ciphertext to scalar k (Enc(m))^k ≡ Enc(k*m)."""
    n2 = n * n
    return pow(c, k, n2)

# --- RSA multiplicative homomorphism “exponent trick”
# We accept pre-formed RSA "homomorphic" ciphertexts from clients and we only
# multiply them mod n. No decryption here.
def rsa_homomorphic_multiply(cipher_list, n):
    """Multiply many RSA ciphertexts mod n (c_agg = Π c_i mod n)."""
    acc = 1 % n
    for c in cipher_list:
        acc = (acc * (c % n)) % n
    return acc

# -----------------------------------------------------------------------------
# Request Handlers
# -----------------------------------------------------------------------------
def handle_register_doctor(state, req):
    """
    Register a doctor (or a generic client entry). Stores:
      - username
      - public keys (RSA, ElGamal, Paillier optional)
      - encrypted department hash (Paillier Enc(hash))
    """
    username = req.get("username", "").strip()
    pub_rsa = req.get("pub_rsa")            # {n,e}
    pub_elg = req.get("pub_elgamal")        # {p,g,y}
    pub_pai = req.get("pub_paillier")       # {n,g} (optional)
    dept_hash_enc_b64 = req.get("dept_hash_enc_b64")  # base64 Paillier ciphertext of hash

    if not username or not isinstance(pub_rsa, dict) or not isinstance(pub_elg, dict):
        return {"ok": False, "err": "Missing username or required public keys."}

    with STATE_LOCK:
        if username in state["doctors"]:
            return {"ok": False, "err": "Username already registered."}
        state["doctors"][username] = {
            "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pubkeys": {
                "rsa": {"n": int(pub_rsa["n"]), "e": int(pub_rsa["e"])},
                "elgamal": {"p": int(pub_elg["p"]), "g": int(pub_elg["g"]), "y": int(pub_elg["y"])},
            },
            "dept_hash_enc": dept_hash_enc_b64 if isinstance(dept_hash_enc_b64, str) else None,
            "records": [],
            "expenses": []
        }
        if isinstance(pub_pai, dict) and "n" in pub_pai and "g" in pub_pai:
            state["doctors"][username]["pubkeys"]["paillier"] = {
                "n": int(pub_pai["n"]),
                "g": int(pub_pai["g"])
            }
        save_state(state)

    return {"ok": True, "data": {"username": username}}

def handle_submit_report(state, req):
    """
    Store an encrypted report with:
      - AES ciphertext (base64 IV||CT)
      - RSA-wrapped AES key (base64)
      - ElGamal signature (r,s) over H(report||timestamp)
    """
    username = req.get("username", "").strip()
    ts = req.get("timestamp", "")
    aes_ct_b64 = req.get("aes_ct_b64", "")
    aes_key_rsa_b64 = req.get("aes_key_rsa_b64", "")
    sig_scheme = req.get("sig_scheme", "ElGamal")
    sig = req.get("signature")  # {r,s}
    h_hex = req.get("hash_hex") # H(message||timestamp) hex string

    if not username or not aes_ct_b64 or not aes_key_rsa_b64 or not h_hex:
        return {"ok": False, "err": "Missing fields for report submission."}
    if sig_scheme != "ElGamal":
        return {"ok": False, "err": "Only ElGamal signature verification supported here."}
    if not isinstance(sig, dict) or "r" not in sig or "s" not in sig:
        return {"ok": False, "err": "Invalid signature format."}

    with STATE_LOCK:
        doc = state["doctors"].get(username)
        if not doc:
            return {"ok": False, "err": "User not registered."}
        pub_elg = doc["pubkeys"].get("elgamal")
        if not pub_elg:
            return {"ok": False, "err": "Missing ElGamal public key for user."}

        # Verify ElGamal signature over hash
        h_int = hexhash_to_int(h_hex, modulus=int(pub_elg["p"]) - 1)
        ok_sig = elgamal_verify(pub_elg, h_int, sig)
        if not ok_sig:
            return {"ok": False, "err": "Signature verification failed."}

        record = {
            "timestamp": ts if ts else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "aes_ct_b64": aes_ct_b64,
            "aes_key_rsa_b64": aes_key_rsa_b64,
            "sig_scheme": "ElGamal",
            "sig": {"r": int(sig["r"]), "s": int(sig["s"])},
            "sig_hash_alg": "SHA-256"
        }
        doc["records"].append(record)
        save_state(state)

    return {"ok": True, "data": {"stored": True}}

def handle_log_expense(state, req):
    """
    Store an RSA-homomorphic ciphertext for an expense.
    The server only stores the ciphertext {c:int}.
    """
    username = req.get("username", "").strip()
    c_obj = req.get("cipher_rsa")
    if not username or not isinstance(c_obj, dict) or "c" not in c_obj:
        return {"ok": False, "err": "Missing username or expense ciphertext."}

    with STATE_LOCK:
        doc = state["doctors"].get(username)
        if not doc:
            return {"ok": False, "err": "User not registered."}
        doc["expenses"].append({
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cipher_rsa": {"c": int(c_obj["c"])}
        })
        save_state(state)

    return {"ok": True, "data": {"logged": True}}

def handle_set_rsa_accumulator_pub(state, req):
    """
    Auditor sets (or updates) global RSA accumulator public params for homomorphic expense summation.
    Fields: n, e, g
    NOTE: 'g' is the base used in the exponent-trick encryption on the client.
    """
    n = req.get("n"); e = req.get("e"); g = req.get("g")
    if not all(isinstance(x, int) and x > 0 for x in [n, e, g]):
        return {"ok": False, "err": "Invalid RSA accumulator parameters."}
    with STATE_LOCK:
        state["keys"]["rsa_accumulator"] = {"n": int(n), "e": int(e), "g": int(g)}
        save_state(state)
    return {"ok": True, "data": {"set": True}}

def handle_get_rsa_accumulator_pub(state, _req):
    with STATE_LOCK:
        params = state["keys"].get("rsa_accumulator")
        if not params:
            return {"ok": False, "err": "RSA accumulator not set."}
        return {"ok": True, "data": params}

def handle_set_paillier_pub(state, req):
    """
    Auditor sets a Paillier public key (n,g) for department searchable encryption.
    Doctors are expected to encrypt hash(dept) with THIS public key when registering.
    """
    n = req.get("n"); g = req.get("g")
    if not all(isinstance(x, int) and x > 0 for x in [n, g]):
        return {"ok": False, "err": "Invalid Paillier public parameters."}
    with STATE_LOCK:
        state["keys"]["paillier_pub"] = {"n": int(n), "g": int(g)}
        save_state(state)
    return {"ok": True, "data": {"set": True}}

def handle_get_paillier_pub(state, _req):
    with STATE_LOCK:
        pub = state["keys"].get("paillier_pub")
        if not pub:
            return {"ok": False, "err": "Paillier public key not set."}
        return {"ok": True, "data": pub}

def handle_search_dept_prepare(state, req):
    """
    Privacy-preserving dept search (two-party):
    Auditor sends Enc(hash(query)) under the SAME Paillier pub key as used by doctors.
    Server returns a list of tuples for each doctor:
       doctor, Enc(hash(doctor_dept) - hash(query))
    The auditor decrypts each and checks for ZERO to identify matches.

    Request:
      { "op":"search_dept_prepare", "enc_query_b64": "<base64 of integer ciphertext>" }

    enc_query_b64 is base64 of big-endian bytes of Paillier ciphertext c_q (int).
    """
    enc_query_b64 = req.get("enc_query_b64", "")
    if not enc_query_b64:
        return {"ok": False, "err": "Missing enc_query_b64."}

    # Decode ciphertext int (big-endian bytes)
    try:
        c_query = int.from_bytes(base64.b64decode(enc_query_b64), byteorder="big")
    except Exception:
        return {"ok": False, "err": "Invalid base64 Paillier ciphertext."}

    with STATE_LOCK:
        pub = state["keys"].get("paillier_pub")
        if not pub:
            return {"ok": False, "err": "Paillier public key not set on server."}
        n = int(pub["n"]); g = int(pub["g"]); n2 = n*n

        out = []
        for uname, doc in state["doctors"].items():
            b64 = doc.get("dept_hash_enc")
            if not b64:
                continue
            try:
                c_doc = int.from_bytes(base64.b64decode(b64), byteorder="big")
            except Exception:
                continue

            # Enc(hash_doc - hash_query) = Enc(hash_doc) * Enc(hash_query)^(-1)
            # (Paillier inverse is modular inverse in Z_{n^2})
            try:
                inv_cq = pow(c_query, -1, n2)
            except ValueError:
                # If not invertible (shouldn't happen for valid Paillier ciphertexts), skip
                continue
            c_diff = (c_doc * inv_cq) % n2

            out.append({
                "doctor": uname,
                "enc_diff_b64": base64.b64encode(c_diff.to_bytes((c_diff.bit_length()+7)//8 or 1, "big")).decode()
            })

        return {"ok": True, "data": {"matches_token": out}}

def handle_aggregate_expenses(state, req):
    """
    Aggregate expenses:
      mode = "all"      -> sum across all doctors
      mode = "per_doctor" and username=... -> sum per specific doctor

    Returns a single RSA ciphertext C_agg (as int) computed by multiplying all c_i modulo n.
    Auditor holding (n,d) removes randomizers by raising C_agg^d mod n to get g^{sum} (mod n),
    then recovers SUM via discrete log base g (client-side routine uses baby-step giant-step).
    """
    mode = req.get("mode", "all")
    target = req.get("username", None)

    with STATE_LOCK:
        acc = state["keys"].get("rsa_accumulator")
        if not acc:
            return {"ok": False, "err": "RSA accumulator not configured."}
        n = int(acc["n"])

        ciphers = []
        if mode == "per_doctor" and target:
            doc = state["doctors"].get(target)
            if not doc:
                return {"ok": False, "err": "Doctor not found."}
            ciphers = [int(x["cipher_rsa"]["c"]) for x in doc.get("expenses", [])]
        else:
            # all doctors
            for _, doc in state["doctors"].items():
                for x in doc.get("expenses", []):
                    ciphers.append(int(x["cipher_rsa"]["c"]))

        if not ciphers:
            return {"ok": True, "data": {"cipher_agg": None, "note": "No expenses present."}}

        c_agg = rsa_homomorphic_multiply(ciphers, n)
        return {"ok": True, "data": {"cipher_agg": int(c_agg), "n": n, "g": int(acc["g"])}}

def handle_list_records(state, _req):
    """
    Return a redacted view of stored records (metadata only, no plaintext).
    """
    with STATE_LOCK:
        out = {}
        for uname, doc in state["doctors"].items():
            out[uname] = {
                "registered_at": doc.get("registered_at"),
                "records_count": len(doc.get("records", [])),
                "expenses_count": len(doc.get("expenses", []))
            }
        return {"ok": True, "data": out}

def handle_list_doctor_detail(state, req):
    """
    Return detail for a specific doctor (still redacted).
    """
    username = req.get("username", "").strip()
    if not username:
        return {"ok": False, "err": "Missing username."}
    with STATE_LOCK:
        doc = state["doctors"].get(username)
        if not doc:
            return {"ok": False, "err": "Doctor not found."}
        return {"ok": True, "data": {
            "registered_at": doc.get("registered_at"),
            "pubkeys": doc.get("pubkeys"),
            "records": [{"timestamp": r["timestamp"], "sig_scheme": r["sig_scheme"]} for r in doc.get("records", [])],
            "expenses_count": len(doc.get("expenses", []))
        }}

# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------
def route_request(state, req):
    op = req.get("op")
    try:
        if op == "register_doctor":
            return handle_register_doctor(state, req)
        elif op == "submit_report":
            return handle_submit_report(state, req)
        elif op == "log_expense":
            return handle_log_expense(state, req)
        elif op == "set_rsa_accumulator_pub":
            return handle_set_rsa_accumulator_pub(state, req)
        elif op == "get_rsa_accumulator_pub":
            return handle_get_rsa_accumulator_pub(state, req)
        elif op == "set_paillier_pub":
            return handle_set_paillier_pub(state, req)
        elif op == "get_paillier_pub":
            return handle_get_paillier_pub(state, req)
        elif op == "search_dept_prepare":
            return handle_search_dept_prepare(state, req)
        elif op == "aggregate_expenses":
            return handle_aggregate_expenses(state, req)
        elif op == "list_records":
            return handle_list_records(state, req)
        elif op == "list_doctor_detail":
            return handle_list_doctor_detail(state, req)
        else:
            return {"ok": False, "err": f"Unknown op: {op}"}
    except Exception as e:
        # Log and return clean error
        traceback.print_exc()
        return {"ok": False, "err": f"Server exception: {e}"}

# -----------------------------------------------------------------------------
# Networking: Threaded TCP JSON server
# -----------------------------------------------------------------------------
class ClientThread(threading.Thread):
    def __init__(self, conn, addr, state):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.state = state

    def run(self):
        try:
            file_r = self.conn.makefile("r", encoding="utf-8", newline="\n")
            file_w = self.conn.makefile("w", encoding="utf-8", newline="\n")
            while True:
                line = file_r.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except Exception:
                    resp = {"ok": False, "err": "Invalid JSON."}
                    file_w.write(json.dumps(resp) + "\n")
                    file_w.flush()
                    continue

                resp = route_request(self.state, req)
                file_w.write(json.dumps(resp) + "\n")
                file_w.flush()
        except Exception:
            traceback.print_exc()
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

def serve(host="127.0.0.1", port=9099):
    print(f"🔐 Secure Lab Server starting at {host}:{port}")
    print("Tip: This server is generic. Change 'record_type' in state if you switch domains.\n")
    state = load_state()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(20)
        print("✅ Listening for clients...")
        while True:
            conn, addr = s.accept()
            print(f"→ Client connected: {addr}")
            th = ClientThread(conn, addr, state)
            th.start()

if __name__ == "__main__":
    serve()
