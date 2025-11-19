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
        """Define os cabeçalhos de resposta padrão (JSON)."""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        """
        Processa a requisição POST.
        Validamos headers e corpo antes de tentar qualquer criptografia.
        """
        try:
            print(f"\n[Kortana Log] Nova requisição recebida de {self.client_address}")

            # 1. Validação Defensiva: O cabeçalho Content-Length existe?
            # Se o cliente (curl) não mandar o tamanho, não podemos ler.
            if 'Content-Length' not in self.headers:
                raise ValueError("Cabeçalho 'Content-Length' ausente. Você enviou dados com -d?")
            
            # 2. Validação de Tamanho
            try:
                content_length = int(self.headers['Content-Length'])
            except (ValueError, TypeError):
                raise ValueError("Content-Length inválido.")

            if content_length <= 0:
                raise ValueError("O corpo da mensagem está vazio. Nada para cifrar!")

            # 3. Leitura do Payload
            plaintext = self.rfile.read(content_length).decode('utf-8')
            print(f"[Kortana Log] Payload recebido ({content_length} bytes). Iniciando criptografia...")

            # 4. Carregamento da Política (com tratamento de erro JSON)
            if not os.path.exists(POLICY_FILE):
                raise FileNotFoundError(f"Arquivo de política '{POLICY_FILE}' não encontrado no servidor.")
            
            try:
                with open(POLICY_FILE, 'r') as f:
                    policy = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Erro de sintaxe no '{POLICY_FILE}'. Verifique as aspas duplas! Detalhe: {str(e)}")

            # 5. Execução do Core Criptográfico
            result_data = self.run_hybrid_encryption(plaintext, policy)

            # 6. Sucesso!
            self._set_headers(200)
            self.wfile.write(json.dumps(result_data).encode('utf-8'))
            print("[Kortana Log] Resposta cifrada enviada com sucesso. ✨")

        except Exception as e:
            # Tratamento global de erros: Devolve JSON mesmo se quebrar
            print(f"[Kortana Error] {str(e)}")
            self._set_headers(400) # Bad Request ou Internal Error
            error_response = {
                "error": str(e),
                "hint": "Verifique se usou -d 'sua mensagem' no curl e se o policy_pqc.json está válido."
            }
            self.wfile.write(json.dumps(error_response).encode('utf-8'))

    def run_hybrid_encryption(self, plaintext, policy):
        """
        Orquestra o OpenSSL para o fluxo híbrido (Kyber + X25519 + AES-GCM).
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            provider_flag = ["-provider", policy['provider'], "-provider", "default"]
            
            # --- PASSO A: KEM Pós-Quântico ---
            kem_alg = policy['kem']
            kem_priv = os.path.join(tmp_dir, "kem_priv.pem")
            kem_pub = os.path.join(tmp_dir, "kem_pub.pem")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            # Gerar chaves e encapsular
            subprocess.run(["openssl", "genpkey", "-algorithm", kem_alg, "-out", kem_priv] + provider_flag, check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", kem_priv, "-pubout", "-out", kem_pub] + provider_flag, check=True, capture_output=True)
            subprocess.run(["openssl", "pkeyutl", "-encap", "-inkey", kem_priv, "-peerform", "PEM", "-peerkey", kem_pub, "-out", kem_ct, "-secret", kem_ss] + provider_flag, check=True, capture_output=True)

            # --- PASSO B: Clássico (X25519) ---
            dh_alg = policy['dh']
            dh_priv_a = os.path.join(tmp_dir, "dh_priv_a.pem")
            dh_priv_b = os.path.join(tmp_dir, "dh_priv_b.pem")
            dh_pub_b = os.path.join(tmp_dir, "dh_pub_b.pem")
            dh_ss = os.path.join(tmp_dir, "dh_ss.bin")

            subprocess.run(["openssl", "genpkey", "-algorithm", dh_alg, "-out", dh_priv_a], check=True, capture_output=True)
            subprocess.run(["openssl", "genpkey", "-algorithm", dh_alg, "-out", dh_priv_b], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", dh_priv_b, "-pubout", "-out", dh_pub_b], check=True, capture_output=True)
            subprocess.run(["openssl", "pkeyutl", "-derive", "-inkey", dh_priv_a, "-peerform", "PEM", "-peerkey", dh_pub_b, "-out", dh_ss], check=True, capture_output=True)

            # --- PASSO C: KDF (Derivação Híbrida) ---
            with open(kem_ss, 'rb') as f: ss_pqc_bytes = f.read()
            with open(dh_ss, 'rb') as f: ss_classic_bytes = f.read()

            kdf = hashlib.sha256()
            kdf.update(ss_pqc_bytes)
            kdf.update(ss_classic_bytes)
            symmetric_key_hex = kdf.digest().hex()

            # --- PASSO D: Cifragem Simétrica (AES-GCM) ---
            iv = os.urandom(12)
            pt_file = os.path.join(tmp_dir, "plaintext.txt")
            ct_file = os.path.join(tmp_dir, "ciphertext.bin")
            tag_file = os.path.join(tmp_dir, "tag.bin")

            with open(pt_file, 'w') as f: f.write(plaintext)

            subprocess.run([
                "openssl", "enc", "-" + policy['symmetric'],
                "-K", symmetric_key_hex,
                "-iv", iv.hex(),
                "-in", pt_file,
                "-out", ct_file,
                "-tag", tag_file
            ], check=True, capture_output=True)

            # Leitura final
            with open(ct_file, 'rb') as f: ct_bytes = f.read()
            with open(tag_file, 'rb') as f: tag_bytes = f.read()
            with open(kem_ct, 'rb') as f: kem_ct_bytes = f.read()
            with open(kem_pub, 'rb') as f: kem_pub_bytes = f.read()
            with open(dh_pub_b, 'rb') as f: dh_pub_bytes = f.read()

            return {
                "ciphertext": base64.b64encode(ct_bytes + tag_bytes).decode('utf-8'),
                "nonce": base64.b64encode(iv).decode('utf-8'),
                "kem_ciphertext": base64.b64encode(kem_ct_bytes).decode('utf-8'),
                "public_keys": {
                    "pqc_kem": base64.b64encode(kem_pub_bytes).decode('utf-8'),
                    "classic_dh": base64.b64encode(dh_pub_bytes).decode('utf-8')
                }
            }

if __name__ == "__main__":
    print(f"🌟 Kortana PQC Server 2.0 (Secure & Robust) iniciado em {HOST_NAME}:{SERVER_PORT}")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass