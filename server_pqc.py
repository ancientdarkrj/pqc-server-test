import os
import json
import subprocess
import base64
import hashlib
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

# --- Configurações Globais ---
POLICY_FILE = 'policy_pqc.json'
HOST_NAME = '0.0.0.0'
SERVER_PORT = 8080

class PQCRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        try:
            print(f"\n[Kortana Log] Request recebido de {self.client_address}")

            if 'Content-Length' not in self.headers:
                raise ValueError("Header 'Content-Length' faltando.")
            
            try:
                content_length = int(self.headers['Content-Length'])
            except (ValueError, TypeError):
                raise ValueError("Content-Length inválido.")

            if content_length <= 0:
                raise ValueError("Corpo da mensagem vazio.")

            plaintext = self.rfile.read(content_length).decode('utf-8')
            
            if not os.path.exists(POLICY_FILE):
                raise FileNotFoundError(f"Política '{POLICY_FILE}' não encontrada.")
            
            with open(POLICY_FILE, 'r') as f:
                policy = json.load(f)

            # Executa a cifragem
            result_data = self.run_hybrid_encryption(plaintext, policy)

            self._set_headers(200)
            self.wfile.write(json.dumps(result_data).encode('utf-8'))
            print("[Kortana Log] Sucesso! Dados cifrados enviados.")

        except Exception as e:
            print(f"[Kortana Error] {str(e)}")
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def run_hybrid_encryption(self, plaintext, policy):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # CORREÇÃO DE ARQUITETURA:
            # Os providers devem ser carregados ANTES de especificar o algoritmo.
            # OpenSSL 3 é rigoroso com a ordem dos argumentos.
            base_cmd = ["openssl", "genpkey", "-provider", policy['provider'], "-provider", "default"]
            base_pkey = ["openssl", "pkey", "-provider", policy['provider'], "-provider", "default"]
            base_util = ["openssl", "pkeyutl", "-provider", policy['provider'], "-provider", "default"]
            
            # --- 1. KEM Pós-Quântico (ML-KEM / Kyber) ---
            kem_alg = policy['kem']
            kem_priv = os.path.join(tmp_dir, "kem_priv.pem")
            kem_pub = os.path.join(tmp_dir, "kem_pub.pem")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            # Gerar chaves (Provider vem antes!)
            subprocess.run(base_cmd + ["-algorithm", kem_alg, "-out", kem_priv], check=True, capture_output=True)
            # Extrair pública
            subprocess.run(base_pkey + ["-in", kem_priv, "-pubout", "-out", kem_pub], check=True, capture_output=True)
            # Encapsular
            subprocess.run(base_util + ["-encap", "-inkey", kem_priv, "-peerform", "PEM", "-peerkey", kem_pub, "-out", kem_ct, "-secret", kem_ss], check=True, capture_output=True)

            # --- 2. Clássico (X25519) ---
            dh_alg = policy['dh']
            dh_priv_a = os.path.join(tmp_dir, "dh_a.pem")
            dh_priv_b = os.path.join(tmp_dir, "dh_b.pem")
            dh_pub_b = os.path.join(tmp_dir, "dh_pub_b.pem")
            dh_ss = os.path.join(tmp_dir, "dh_ss.bin")

            # X25519 é nativo, mas mal não faz carregar os providers também
            subprocess.run(base_cmd + ["-algorithm", dh_alg, "-out", dh_priv_a], check=True)
            subprocess.run(base_cmd + ["-algorithm", dh_alg, "-out", dh_priv_b], check=True)
            subprocess.run(base_pkey + ["-in", dh_priv_b, "-pubout", "-out", dh_pub_b], check=True)
            subprocess.run(base_util + ["-derive", "-inkey", dh_priv_a, "-peerform", "PEM", "-peerkey", dh_pub_b, "-out", dh_ss], check=True)

            # --- 3. Derivação (KDF) ---
            with open(kem_ss, 'rb') as f: ss_pqc = f.read()
            with open(dh_ss, 'rb') as f: ss_dh = f.read()
            
            kdf = hashlib.sha256()
            kdf.update(ss_pqc)
            kdf.update(ss_dh)
            sym_key = kdf.digest().hex()

            # --- 4. Cifrar AES-GCM ---
            iv = os.urandom(12)
            pt_file = os.path.join(tmp_dir, "pt.txt")
            ct_file = os.path.join(tmp_dir, "ct.bin")
            tag_file = os.path.join(tmp_dir, "tag.bin")
            
            with open(pt_file, 'w') as f: f.write(plaintext)
            
            # Comando de encriptação (Provider também é bom estar lá)
            enc_cmd = ["openssl", "enc", "-" + policy['symmetric'], 
                       "-provider", policy['provider'], "-provider", "default",
                       "-K", sym_key, "-iv", iv.hex(), 
                       "-in", pt_file, "-out", ct_file, "-tag", tag_file]
            
            subprocess.run(enc_cmd, check=True, capture_output=True)

            with open(ct_file, 'rb') as f: ct = f.read()
            with open(tag_file, 'rb') as f: tag = f.read()
            with open(kem_ct, 'rb') as f: k_ct_b = f.read()
            with open(kem_pub, 'rb') as f: k_pub_b = f.read()
            with open(dh_pub_b, 'rb') as f: dh_pub_b = f.read()

            return {
                "ciphertext": base64.b64encode(ct + tag).decode('utf-8'),
                "nonce": base64.b64encode(iv).decode('utf-8'),
                "kem_ciphertext": base64.b64encode(k_ct_b).decode('utf-8'),
                "public_keys": {
                    "pqc": base64.b64encode(k_pub_b).decode('utf-8'),
                    "classic": base64.b64encode(dh_pub_b).decode('utf-8')
                }
            }

if __name__ == "__main__":
    print(f"Kortana Server 3.0 (Fixed Order) rodando na porta {SERVER_PORT}")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    server.serve_forever()