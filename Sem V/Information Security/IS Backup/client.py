#!/usr/bin/env python3
# client.py — Generic Secure Computation Client (Labs 4–8, domain-agnostic)
# -----------------------------------------------------------------------------
# Single menu-driven client that can:
#  - Generate RSA / ElGamal / Paillier keys (local)
#  - Register an "entity" on the server (no fixed roles)
#  - Encrypt & submit records (AES-256-GCM + RSA wrap, ElGamal signature)
#  - Log encrypted numeric values for multiplicative aggregation (RSA group demo)
#  - Configure Paillier public key on server and perform encrypted equality search
#  - Request aggregated ciphertext and recover SUM (via discrete log with bound)
#  - Run Lab-7 demos: Paillier addition, RSA multiplicative aggregation (demo)
#  - Run Lab-8 demos: SSE (AES) and PKSE (Paillier) searchable encryption (toy)
#
# Dependencies: pip install pycryptodome
# -----------------------------------------------------------------------------

import os, sys, json, base64, socket, hashlib, math, random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, GCD, inverse, bytes_to_long, long_to_bytes

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9099

# --------------------- Networking ---------------------
def send_req(obj):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    f = s.makefile("rw", encoding="utf-8", newline="\n")
    f.write(json.dumps(obj) + "\n"); f.flush()
    line = f.readline()
    s.close()
    if not line: return {"ok": False, "err": "No response"}
    try:
        return json.loads(line)
    except Exception:
        return {"ok": False, "err": "Bad JSON from server"}

# --------------------- Key Material (local) ---------------------
LOCAL = {
    "domain": "generic",
    "me": None,             # username
    "rsa": None,            # {"n","e","d"}
    "elgamal": None,        # {"p","g","x","y"}
    "paillier": None,       # {"p","q","n","g","lam","mu"}   (g=n+1 form)
    "rsa_group": None       # {"n","g"} for lab aggregation
}

def set_domain():
    d = input("Enter domain label (e.g., medical/banking/ids) [generic]: ").strip() or "generic"
    LOCAL["domain"] = d
    print("✅ Domain set to:", d)

# --------------------- RSA ---------------------
def gen_rsa(bits=2048):
    k = RSA.generate(bits)
    n = k.n; e = k.e; d = k.d
    LOCAL["rsa"] = {"n": n, "e": e, "d": d}
    print("✅ RSA generated (n,e).")

# --------------------- ElGamal (signing) ---------------------
def gen_elgamal(bits=2048):
    # Simple construction: pick large prime p (not necessarily safe), generator g=2
    # For lab use only.
    p = getPrime(bits)
    g = 2
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    LOCAL["elgamal"] = {"p": p, "g": g, "x": x, "y": y}
    print("✅ ElGamal generated.")

def elgamal_sign(hash_hex: str, sk: dict):
    p = sk["p"]; g = sk["g"]; x = sk["x"]
    h = int(hash_hex, 16) % (p-1)
    while True:
        k = random.randrange(2, p-2)
        if GCD(k, p-1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x*r) * inverse(k, p-1)) % (p-1)
    return {"r": int(r), "s": int(s)}

# --------------------- Paillier (n=gcd) ---------------------
def gen_paillier(bits=1024):
    # g = n + 1 form, lambda = lcm(p-1,q-1), mu = (L(g^lambda mod n^2))^{-1} mod n
    while True:
        p = getPrime(bits//2)
        q = getPrime(bits//2)
        if p != q and GCD(p*q, (p-1)*(q-1)) == 1:
            break
    n = p*q
    g = n + 1
    lam = ( (p-1)*(q-1) ) // math.gcd(p-1, q-1)
    n2 = n*n
    def L(u): return (u-1)//n
    mu = inverse(L(pow(g, lam, n2)), n)
    LOCAL["paillier"] = {"p": p, "q": q, "n": n, "g": g, "lam": lam, "mu": mu}
    print("✅ Paillier generated (n,g).")

def paillier_encrypt(m: int, pub: dict):
    n = pub["n"]; g = pub["g"]; n2 = n*n
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c

def paillier_decrypt(c: int, sec: dict):
    n = sec["n"]; g = sec["g"]; lam = sec["lam"]; mu = sec["mu"]; n2 = n*n
    u = pow(c, lam, n2)
    L = (u - 1) // n
    m = (L * mu) % n
    return m

# --------------------- AES-256-GCM helpers ---------------------
def aes_gcm_encrypt(plaintext: bytes, aad: bytes = b""):
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    blob = nonce + ct + tag
    return key, base64.b64encode(blob).decode()

def aes_gcm_decrypt(key: bytes, b64_blob: str, aad: bytes = b""):
    blob = base64.b64decode(b64_blob)
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt

# Wrap/unwrap via RSA (PKCS1_OAEP)
def rsa_wrap(key_bytes: bytes, rsa_pub_n: int, rsa_pub_e: int):
    pub = RSA.construct((rsa_pub_n, rsa_pub_e))
    cipher = PKCS1_OAEP.new(pub)
    return base64.b64encode(cipher.encrypt(key_bytes)).decode()

def rsa_unwrap(b64: str, rsa_priv_d: int, rsa_n: int, rsa_e: int):
    priv = RSA.construct((rsa_n, rsa_e, rsa_priv_d))
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(base64.b64decode(b64))

# --------------------- Discrete log (for lab aggregation) ---------------------
def baby_step_giant_step(g, h, n, bound):
    # Solve g^x ≡ h (mod n) with x in [0, bound], returns x or None
    m = int(math.ceil(math.sqrt(bound+1)))
    table = {}
    e = 1
    for j in range(m):
        table[e] = j
        e = (e * g) % n
    inv_gm = pow(pow(g, m, n), -1, n)
    gamma = h % n
    for i in range(m+1):
        if gamma in table:
            return i*m + table[gamma]
        gamma = (gamma * inv_gm) % n
    return None

# --------------------- Menus & Workflows ---------------------
def menu_keygen():
    print("\n== Key Generation ==")
    print("1) RSA  2) ElGamal  3) Paillier  4) Back")
    ch = input("Choice: ").strip()
    if ch == "1": gen_rsa()
    elif ch == "2": gen_elgamal()
    elif ch == "3": gen_paillier()
    else: return

def menu_register_entity():
    if not LOCAL["me"]:
        me = input("Choose a username for this entity: ").strip()
        if not me:
            print("❌ username required"); return
        LOCAL["me"] = me
    if not (LOCAL["rsa"] and LOCAL["elgamal"]):
        print("❌ Need RSA and ElGamal keys first (menu: Key Generation).")
        return
    # Optional: include Paillier pub in registration
    pub_paillier = None
    if LOCAL["paillier"]:
        pub_paillier = {"n": LOCAL["paillier"]["n"], "g": LOCAL["paillier"]["g"]}

    # Optional searchable field: Paillier Enc(hash(keyword))
    searchable_b64 = None
    use_search = input("Attach searchable field (Paillier Enc(hash(keyword)))? [y/N]: ").strip().lower() == "y"
    if use_search:
        if not LOCAL["paillier"]:
            print("❌ Generate Paillier first.")
            return
        kw = input("Enter keyword for this entity (e.g., department or tag): ").strip()
        h = hashlib.sha256(kw.encode()).hexdigest()
        m = int(h, 16) % LOCAL["paillier"]["n"]
        c = paillier_encrypt(m, {"n": LOCAL["paillier"]["n"], "g": LOCAL["paillier"]["g"]})
        searchable_b64 = base64.b64encode(c.to_bytes((c.bit_length()+7)//8 or 1, "big")).decode()

    req = {
        "op": "register_entity",
        "username": LOCAL["me"],
        "pubkeys": {
            "rsa": {"n": LOCAL["rsa"]["n"], "e": LOCAL["rsa"]["e"]},
            "elgamal": {"p": LOCAL["elgamal"]["p"], "g": LOCAL["elgamal"]["g"], "y": LOCAL["elgamal"]["y"]},
        },
        "searchable_b64": searchable_b64
    }
    if pub_paillier: req["pubkeys"]["paillier"] = pub_paillier
    resp = send_req(req)
    print(resp)

def menu_submit_record():
    if not (LOCAL["me"] and LOCAL["rsa"] and LOCAL["elgamal"]):
        print("❌ Need username + RSA + ElGamal.")
        return
    plaintext = input("Enter plaintext record (json/text): ").encode()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    digest = hashlib.sha256(plaintext + ts.encode()).hexdigest()

    # AES-GCM encrypt
    key, b64_ct = aes_gcm_encrypt(plaintext, aad=ts.encode())
    # RSA-wrap AES key (with *own* RSA public for demo; can be server/auditor pub in other setups)
    b64_wrap = rsa_wrap(key, LOCAL["rsa"]["n"], LOCAL["rsa"]["e"])
    # ElGamal sign the digest
    sig = elgamal_sign(digest, LOCAL["elgamal"])

    req = {
        "op": "submit_record",
        "username": LOCAL["me"],
        "ts": ts,
        "aes_gcm_b64": b64_ct,
        "aes_key_wrap_b64": b64_wrap,
        "sig": sig,
        "hash_hex": digest
    }
    resp = send_req(req)
    print(resp)

def menu_set_paillier_pub_on_server():
    if not LOCAL["paillier"]:
        print("❌ Generate Paillier first.")
        return
    req = {"op": "set_paillier_pub", "n": LOCAL["paillier"]["n"], "g": LOCAL["paillier"]["g"]}
    print(send_req(req))

def menu_search_equality():
    print("\n== Encrypted Equality Search (Paillier) ==")
    # Ensure server has Paillier pub
    pub = send_req({"op": "get_paillier_pub"})
    if not pub.get("ok"):
        print("❌", pub.get("err")); return
    n = pub["data"]["n"]; g = pub["data"]["g"]

    kw = input("Enter search keyword: ").strip()
    m = int(hashlib.sha256(kw.encode()).hexdigest(), 16) % n
    c = paillier_encrypt(m, {"n": n, "g": g})
    enc_q_b64 = base64.b64encode(c.to_bytes((c.bit_length()+7)//8 or 1, "big")).decode()
    res = send_req({"op": "search_field_prepare", "enc_query_b64": enc_q_b64})
    if not res.get("ok"):
        print("❌", res.get("err")); return
    tokens = res["data"]["tokens"]
    print("→ Server returned tokens for entities:", len(tokens))
    if not LOCAL["paillier"] or LOCAL["paillier"]["n"] != n:
        print("Note: You need the matching Paillier private key to zero-test; skipping decrypt.")
        return
    # Decrypt each diff and check zero
    matches = []
    for t in tokens:
        cdiff = int.from_bytes(base64.b64decode(t["enc_diff_b64"]), "big")
        dec = paillier_decrypt(cdiff, LOCAL["paillier"])
        if dec == 0:
            matches.append(t["username"])
    print("✅ Matches:", matches or "None")

def menu_set_rsa_group_on_server():
    # For lab demo, pick a random RSA modulus n (~1024 bits) and base g in [2..n-2]
    print("Generating RSA-group (lab) params n,g ...")
    # NOTE: this is NOT a true group generator step; it's a lab-friendly integer modulus
    p = getPrime(512); q = getPrime(512); n = p*q
    g = random.randrange(2, n-1)
    LOCAL["rsa_group"] = {"n": n, "g": g}
    print(send_req({"op": "set_rsa_group", "n": n, "g": g}))

def menu_log_value():
    if not LOCAL["me"]:
        print("❌ Set username via Register Entity first.")
        return
    grp = send_req({"op": "get_rsa_group"})
    if not grp.get("ok"):
        print("❌", grp.get("err")); return
    n = grp["data"]["n"]; g = grp["data"]["g"]
    v = int(input("Enter non-negative integer value to encrypt/log: ").strip())
    c = pow(g, v, n)  # simplified lab demo (no blinding)
    print(send_req({"op": "log_value", "username": LOCAL["me"], "cipher_obj": {"c": int(c)}}))

def menu_aggregate_and_recover():
    grp = send_req({"op": "get_rsa_group"})
    if not grp.get("ok"):
        print("❌", grp.get("err")); return
    n = grp["data"]["n"]; g = grp["data"]["g"]
    mode = input("Mode [all/per_entity]: ").strip() or "all"
    req = {"op": "aggregate_values", "mode": mode}
    if mode == "per_entity":
        uname = input("Entity username: ").strip()
        req["username"] = uname
    res = send_req(req)
    if not res.get("ok"):
        print("❌", res.get("err")); return
    data = res["data"]
    if not data["cipher_agg"]:
        print("ℹ️ Empty set. Nothing to recover."); return
    cagg = int(data["cipher_agg"])
    # We need to solve g^X = cagg (mod n) with a known bound.
    bound = int(input("Enter max bound for SUM (discrete log search bound): ").strip() or "100000")
    x = baby_step_giant_step(g, cagg, n, bound)
    print("Recovered SUM =", x if x is not None else "Not found within bound")

def menu_list_entities():
    print(send_req({"op": "list_entities"}))

def menu_entity_detail():
    uname = input("Username: ").strip()
    print(send_req({"op": "entity_detail", "username": uname}))

# --------------------- Lab 7 Demos ---------------------
def demo_paillier_addition():
    print("\n== Lab-7: Paillier Additive Homomorphism Demo ==")
    if not LOCAL["paillier"]:
        gen_paillier()
    n = LOCAL["paillier"]["n"]; g = LOCAL["paillier"]["g"]
    a = int(input("a: ").strip()); b = int(input("b: ").strip())
    c1 = paillier_encrypt(a, {"n": n, "g": g})
    c2 = paillier_encrypt(b, {"n": n, "g": g})
    csum = (c1 * c2) % (n*n)
    asum = paillier_decrypt(csum, LOCAL["paillier"])
    print(f"Enc(a)={c1}\nEnc(b)={c2}\nEnc(a+b)={csum}\nDec(a+b)={asum}")

def demo_rsa_multiplicative():
    print("\n== Lab-7: RSA Multiplicative Aggregation (Simplified) ==")
    # Set or get group
    grp = send_req({"op": "get_rsa_group"})
    if not grp.get("ok"):
        print("Server RSA group missing; creating...")
        menu_set_rsa_group_on_server()
        grp = send_req({"op": "get_rsa_group"})
    n = grp["data"]["n"]; g = grp["data"]["g"]
    x = int(input("x: ").strip()); y = int(input("y: ").strip())
    cx = pow(g, x, n); cy = pow(g, y, n)
    cxy = (cx * cy) % n
    bound = int(input("Discrete log bound (>= x+y): ").strip() or "100000")
    rec = baby_step_giant_step(g, cxy, n, bound)
    print(f"cx={cx}\ncy={cy}\nagg={cxy}\nRecovered x+y={rec}")

# --------------------- Lab 8 Demos ---------------------
def demo_sse_aes():
    print("\n== Lab-8: SSE (AES-based toy) ==")
    docs = {}
    k = get_random_bytes(32)  # shared key
    # build encrypted inverted index: hash(word)-> list of encrypted doc_ids
    inv = {}
    n_docs = int(input("How many docs (>=3)? ").strip() or "3")
    for i in range(1, n_docs+1):
        txt = input(f"doc{i} text: ").strip()
        docs[f"doc{i}"] = txt
        for w in txt.split():
            h = hashlib.sha256(w.encode()).digest()
            inv.setdefault(h, []).append(f"doc{i}")
    # encrypt doc_ids
    enc_index = {}
    for h, ids in inv.items():
        iv = get_random_bytes(12)
        cipher = AES.new(k, AES.MODE_GCM, nonce=iv)
        pt = ("|".join(ids)).encode()
        ct, tag = cipher.encrypt_and_digest(pt)
        enc_index[h] = iv + ct + tag
    q = input("Query word: ").strip()
    hq = hashlib.sha256(q.encode()).digest()
    if hq in enc_index:
        blob = enc_index[hq]
        iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
        cipher = AES.new(k, AES.MODE_GCM, nonce=iv)
        pt = cipher.decrypt_and_verify(ct, tag).decode()
        print("Matched docs:", pt.split("|"))
    else:
        print("No match.")

def demo_pkse_paillier():
    print("\n== Lab-8: PKSE (Paillier-based toy) ==")
    if not LOCAL["paillier"]: gen_paillier()
    n = LOCAL["paillier"]["n"]; g = LOCAL["paillier"]["g"]
    # corpus
    docs = {}
    inv = {}
    n_docs = int(input("How many docs (>=3)? ").strip() or "3")
    for i in range(1, n_docs+1):
        txt = input(f"doc{i} text: ").strip()
        docs[f"doc{i}"] = txt
        for w in txt.split():
            h = int(hashlib.sha256(w.encode()).hexdigest(), 16) % n
            inv.setdefault(h, set()).add(f"doc{i}")
    # encrypt index keys and doc IDs (toy: encrypt doc IDs as small ints)
    enc_index = {}
    for h, idset in inv.items():
        ch = paillier_encrypt(h, {"n": n, "g": g})
        enc_ids = [paillier_encrypt(i, {"n": n, "g": g}) for i, _ in enumerate(idset, start=1)]
        enc_index[ch] = enc_ids
    q = input("Query word: ").strip()
    hq = int(hashlib.sha256(q.encode()).hexdigest(), 16) % n
    cq = paillier_encrypt(hq, {"n": n, "g": g})
    # search by equality comparing ciphertext integers (toy approach:
    # in practice we'd need oblivious comparison; here we simply check keys equal)
    matches = []
    for ch, enc_ids in enc_index.items():
        if ch == cq:
            for cdoc in enc_ids:
                did = paillier_decrypt(cdoc, LOCAL["paillier"])
                matches.append(f"doc{did}")
    print("Matches:", matches or "None")

# --------------------- Main Menu ---------------------
def main():
    print("💡 Generic Secure Client (Labs 4–8) — two-file framework")
    while True:
        print("\n== Main ==")
        print("0) Set Domain Label")
        print("1) Key Generation")
        print("2) Register Entity (generic)")
        print("3) Submit Encrypted Record (AES-GCM + RSA wrap + ElGamal sig)")
        print("4) Set Paillier PubKey on Server")
        print("5) Encrypted Equality Search (Paillier)")
        print("6) Set RSA Group on Server (Lab Aggregation)")
        print("7) Log Encrypted Value (RSA group demo)")
        print("8) Aggregate & Recover SUM (discrete log)")
        print("9) List Entities")
        print("10) Entity Detail")
        print("11) Lab-7: Paillier Addition Demo")
        print("12) Lab-7: RSA Multiplicative Aggregation Demo")
        print("13) Lab-8: SSE (AES) Toy Demo")
        print("14) Lab-8: PKSE (Paillier) Toy Demo")
        print("15) Exit")
        ch = input("Choice: ").strip()
        if ch == "0": set_domain()
        elif ch == "1": menu_keygen()
        elif ch == "2": menu_register_entity()
        elif ch == "3": menu_submit_record()
        elif ch == "4": menu_set_paillier_pub_on_server()
        elif ch == "5": menu_search_equality()
        elif ch == "6": menu_set_rsa_group_on_server()
        elif ch == "7": menu_log_value()
        elif ch == "8": menu_aggregate_and_recover()
        elif ch == "9": menu_list_entities()
        elif ch == "10": menu_entity_detail()
        elif ch == "11": demo_paillier_addition()
        elif ch == "12": demo_rsa_multiplicative()
        elif ch == "13": demo_sse_aes()
        elif ch == "14": demo_pkse_paillier()
        else:
            print("Bye!"); break

if __name__ == "__main__":
    from datetime import datetime
    main()
