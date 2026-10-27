#!/usr/bin/env python3
import json
import os
import random
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Menggunakan utils.py bawaan proyek tanpa modifikasi
import utils

PORT = 8000

def xor_cipher(text: str, secret: int) -> str:
    """Enkripsi/dekripsi simetris berbasis stream XOR dengan seed Kunci Sesi DH."""
    plain_bytes = text.encode('utf-8')
    state = secret & 0xFFFFFFFFFFFFFFFF
    keystream = bytearray()
    for _ in range(len(plain_bytes)):
        state = (6364136223846793005 * state + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        keystream.append((state >> 33) & 0xFF)
    return bytes([b ^ k for b, k in zip(plain_bytes, keystream)]).hex()

def xor_decipher(hex_str: str, secret: int) -> str:
    """Dekripsi paket hex menggunakan kunci sesi DH."""
    cipher_bytes = bytes.fromhex(hex_str)
    state = secret & 0xFFFFFFFFFFFFFFFF
    keystream = bytearray()
    for _ in range(len(cipher_bytes)):
        state = (6364136223846793005 * state + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        keystream.append((state >> 33) & 0xFF)
    return bytes([b ^ k for b, k in zip(cipher_bytes, keystream)]).decode('utf-8', errors='ignore')

# State Pemilu In-Memory
class ElectionState:
    def __init__(self):
        self.bits = 32  # Default 32-bit untuk demo interaktif cepat dan mudah diverifikasi
        self.p = None
        self.g = None
        self.kpu_public_key = None   # (p, g, y)
        self.kpu_private_key = None  # x
        self.ballots = []            # list of {id, nik, name, c1, c2, timestamp, receipt}
        self.voted_niks = set()
        self.is_closed = False
        self.tally_results = None
        self.audit_proofs = []
        self.active_dh_sessions = {} # session_id -> {server_priv_b, server_pub_B, shared_key}
        self.last_math_log = {}

        self.init_system(bits=32)

    def init_system(self, bits=32):
        self.bits = bits
        self.p = utils.generate_prime_number(bits)
        self.g = utils.find_primitive_root(self.p)
        
        # Pembangkitan Kunci ElGamal KPU
        elg = utils.ElGamal(p=self.p, g=self.g)
        self.kpu_public_key, self.kpu_private_key = elg.generate_keypair()
        
        self.ballots = []
        self.voted_niks = set()
        self.is_closed = False
        self.tally_results = None
        self.audit_proofs = []
        self.active_dh_sessions = {}
        self.last_math_log = {
            "setup": {
                "bits": self.bits,
                "p": self.p,
                "g": self.g,
                "kpu_x": self.kpu_private_key,
                "kpu_y": self.kpu_public_key[2],
                "formula_y": f"y = {self.g}^{self.kpu_private_key} mod {self.p} = {self.kpu_public_key[2]}"
            }
        }

election = ElectionState()

CANDIDATES = [
    {
        "id": 1,
        "number": "01",
        "name": "Anies R. Baswedan & Muhaimin Iskandar",
        "tagline": "Koalisi Perubahan untuk Persatuan",
        "badge": "Paslon 01"
    },
    {
        "id": 2,
        "number": "02",
        "name": "Prabowo Subianto & Gibran Rakabuming",
        "tagline": "Koalisi Indonesia Maju",
        "badge": "Paslon 02"
    },
    {
        "id": 3,
        "number": "03",
        "name": "Ganjar Pranowo & Mahfud MD",
        "tagline": "Gerak Cepat Indonesia Unggul",
        "badge": "Paslon 03"
    }
]

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Meredam log terminal standar agar rapi
        return

    def _send_json(self, data, status=200):
        response_bytes = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(response_bytes)

    def _read_json(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        return json.loads(post_data.decode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "index.html not found")
            return

        elif path == "/api/status":
            self._send_json({
                "status": "success",
                "election": {
                    "is_closed": election.is_closed,
                    "bits": election.bits,
                    "p": election.p,
                    "g": election.g,
                    "kpu_public_key": {
                        "p": election.kpu_public_key[0],
                        "g": election.kpu_public_key[1],
                        "y": election.kpu_public_key[2]
                    },
                    "total_ballots": len(election.ballots),
                    "ballots_preview": [
                        {
                            "id": b["id"],
                            "nik_masked": b["nik"][:4] + "****" + b["nik"][-4:] if len(b["nik"]) >= 8 else b["nik"],
                            "c1": b["c1"],
                            "c2": b["c2"],
                            "timestamp": b["timestamp"],
                            "receipt": b["receipt"]
                        } for b in election.ballots
                    ],
                    "tally_results": election.tally_results,
                    "audit_proofs": election.audit_proofs
                },
                "candidates": CANDIDATES,
                "last_math_log": election.last_math_log
            })
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/setup":
            data = self._read_json()
            bits = int(data.get("bits", 32))
            election.init_system(bits=bits)
            self._send_json({
                "status": "success",
                "message": f"Sistem pemilu berhasil diinisialisasi ulang ({bits}-bit).",
                "p": election.p,
                "g": election.g,
                "kpu_y": election.kpu_public_key[2],
                "math_log": election.last_math_log["setup"]
            })
            return

        elif path == "/api/dh-handshake":
            # Tahap Diffie-Hellman: Client mengirim A = g^a mod p
            data = self._read_json()
            client_pub_A = int(data.get("client_pub_A"))
            session_id = str(random.getrandbits(64))

            # Server membangkitkan private key b acak
            server_priv_b = random.randint(2, election.p - 2)
            server_pub_B = pow(election.g, server_priv_b, election.p)

            # Server menghitung shared secret K_server = A^b mod p
            server_shared_k = pow(client_pub_A, server_priv_b, election.p)

            election.active_dh_sessions[session_id] = {
                "server_priv_b": server_priv_b,
                "server_pub_B": server_pub_B,
                "shared_key": server_shared_k,
                "created_at": time.time()
            }

            election.last_math_log["dh"] = {
                "p": election.p,
                "g": election.g,
                "client_pub_A": client_pub_A,
                "server_priv_b": server_priv_b,
                "server_pub_B": server_pub_B,
                "shared_key": server_shared_k,
                "formula_B": f"B = {election.g}^{server_priv_b} mod {election.p} = {server_pub_B}",
                "formula_K": f"K = {client_pub_A}^{server_priv_b} mod {election.p} = {server_shared_k}"
            }

            self._send_json({
                "status": "success",
                "session_id": session_id,
                "server_pub_B": server_pub_B,
                "math_steps": election.last_math_log["dh"]
            })
            return

        elif path == "/api/cast-vote":
            if election.is_closed:
                self._send_json({"status": "error", "message": "Pemungutan suara telah ditutup oleh KPU!"}, 400)
                return

            data = self._read_json()
            session_id = data.get("session_id")
            nik = data.get("nik", "").strip()
            name = data.get("name", "").strip()
            encrypted_payload_hex = data.get("encrypted_payload_hex")
            claimed_c1 = int(data.get("c1"))
            claimed_c2 = int(data.get("c2"))

            # Validasi NIK (satu orang satu suara)
            if nik in election.voted_niks:
                self._send_json({
                    "status": "error",
                    "message": f"DITOLAK: Pemilih dengan NIK {nik} sudah pernah menggunakan hak suaranya!"
                }, 400)
                return

            # Validasi sesi DH
            session_data = election.active_dh_sessions.get(session_id)
            if not session_data:
                self._send_json({"status": "error", "message": "Sesi Diffie-Hellman tidak valid atau sudah kedaluwarsa."}, 400)
                return

            server_shared_k = session_data["shared_key"]

            # Dekripsi paket kanal aman DH
            try:
                decrypted_json_str = xor_decipher(encrypted_payload_hex, server_shared_k)
                payload = json.loads(decrypted_json_str)
            except Exception as e:
                self._send_json({"status": "error", "message": f"Dekripsi kanal DH gagal: Integritas data rusak! ({e})"}, 400)
                return

            # Pastikan ciphertext di dalam payload cocok dengan yang dikirim
            payload_c1 = int(payload.get("c1"))
            payload_c2 = int(payload.get("c2"))
            if payload_c1 != claimed_c1 or payload_c2 != claimed_c2:
                self._send_json({"status": "error", "message": "Verifikasi integritas payload gagal!"}, 400)
                return

            # Simpan surat suara terenkripsi ke Kotak Suara Digital KPU
            ballot_id = len(election.ballots) + 1
            receipt_code = f"VOTE-{int(time.time())}-{random.randint(1000, 9999)}"
            ballot_entry = {
                "id": ballot_id,
                "nik": nik,
                "name": name,
                "c1": payload_c1,
                "c2": payload_c2,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "receipt": receipt_code,
                "wire_hex": encrypted_payload_hex
            }
            election.ballots.append(ballot_entry)
            election.voted_niks.add(nik)

            # Catat log matematika ElGamal voter
            math_info = data.get("math_steps", {})
            election.last_math_log["elgamal_encrypt"] = math_info

            self._send_json({
                "status": "success",
                "message": "Surat suara berhasil diamankan dan dimasukkan ke dalam Kotak Suara Digital KPU.",
                "receipt": receipt_code,
                "ballot_id": ballot_id,
                "total_ballots": len(election.ballots)
            })
            return

        elif path == "/api/tally":
            if len(election.ballots) == 0:
                self._send_json({"status": "error", "message": "Belum ada suara yang masuk ke kotak suara!"}, 400)
                return

            # KPU menutup pemilihan dan membuka Private Key ElGamal x
            election.is_closed = True
            counts = {c["id"]: 0 for c in CANDIDATES}
            audit_proofs = []

            p = election.p
            x = election.kpu_private_key

            # Dekripsi setiap suara satu per satu dengan menampilkan tahapan matematika
            for b in election.ballots:
                c1 = b["c1"]
                c2 = b["c2"]

                # 1. Rekonstruksi masker s = c1^x mod p
                s = pow(c1, x, p)

                # 2. Hitung invers modular s^(-1) mod p menggunakan Extended Euclidean
                s_inv = utils.mod_inverse(s, p)

                # 3. Pulihkan pesan asli m = (c2 * s_inv) mod p
                m = (c2 * s_inv) % p

                # Catat ke hitungan jika valid
                if m in counts:
                    counts[m] += 1
                    cand_name = next(c["name"] for c in CANDIDATES if c["id"] == m)
                else:
                    cand_name = f"Suara Tidak Sah (ID: {m})"

                audit_proofs.append({
                    "ballot_id": b["id"],
                    "nik_masked": b["nik"][:4] + "****" + b["nik"][-4:] if len(b["nik"]) >= 8 else b["nik"],
                    "c1": c1,
                    "c2": c2,
                    "recovered_s": s,
                    "s_inv": s_inv,
                    "decrypted_candidate_id": m,
                    "candidate_name": cand_name,
                    "formula_s": f"s = {c1}^{x} mod {p} = {s}",
                    "formula_inv": f"s^{{-1}} mod {p} = {s_inv}",
                    "formula_m": f"m = ({c2} * {s_inv}) mod {p} = {m}"
                })

            total_valid = len(election.ballots)
            tally_summary = []
            for c in CANDIDATES:
                cid = c["id"]
                cnt = counts[cid]
                pct = round((cnt / total_valid) * 100, 1) if total_valid > 0 else 0
                tally_summary.append({
                    "id": cid,
                    "number": c["number"],
                    "name": c["name"],
                    "badge": c["badge"],
                    "count": cnt,
                    "percentage": pct
                })

            election.tally_results = tally_summary
            election.audit_proofs = audit_proofs
            election.last_math_log["elgamal_decrypt"] = audit_proofs[-1] if audit_proofs else {}

            self._send_json({
                "status": "success",
                "message": "Pemilihan resmi ditutup. Kotak suara didekripsi menggunakan Kunci Privat KPU.",
                "tally": tally_summary,
                "audit_proofs": audit_proofs,
                "kpu_private_key_x": election.kpu_private_key
            })
            return

        elif path == "/api/reset":
            election.init_system(bits=election.bits)
            self._send_json({
                "status": "success",
                "message": "Pemilu berhasil di-reset. Kotak suara dikosongkan dan parameter baru dibangkitkan."
            })
            return

        self.send_error(404, "Not Found")

def run():
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"===========================================================")
    print(f"  KPU E-Voting Cryptographic Server running on port {PORT}")
    print(f"  Buka browser di: http://localhost:{PORT}")
    print(f"  (100% Built-in Python Standard Library, Zero Dependencies)")
    print(f"===========================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
        httpd.server_close()

if __name__ == "__main__":
    run()
