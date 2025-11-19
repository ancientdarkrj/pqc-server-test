import os
import json
import subprocess
import base64
import hashlib
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

# --- Configurações ---
HOST_NAME = '0.0.0.0'
SERVER_PORT = 8080

# Algoritmo fixo para garantir estabilidade (Kyber768 / ML-KEM)
TARGET_ALGORITHM = "kyber768"

class PQCRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        try:
            print(f"\n[Kortana Log] Request recebido de {self.client_address}")

            # 1. Validações Básicas
            if 'Content-Length' not in self.headers:
                raise ValueError("Header 'Content-Length' ausente.")
            
            try:
                content_length = int(self.headers['Content-Length'])
            except:
                raise ValueError("Content-Length inválido.")

            if content_length <= 0:
                raise ValueError("Payload vazio.")

            plaintext = self.rfile.read(content_length).decode('utf-8')
            
            # 2. Descobrir onde o provider está escondido (Auto-Discovery)
            provider_path = self.find_provider_path()
            print(f"[Kortana Log] Provider encontrado em: {provider_path}")

            # 3. Executar Criptografia
            result_data = self.run_hybrid_encryption(plaintext, provider_path)

            self._set_headers(200)
            self.wfile.write(json.dumps(result_data).encode('utf-8'))
            print("[Kortana Log] Sucesso Absoluto! 🚀")

        except Exception as e:
            print(f"[Kortana Error] {str(e)}")
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def find_provider_path(self):
        """
        Procura a pasta correta onde o oqsprovider.so está instalado.
        Isso evita o erro de caminhos concatenados com ':'
        """
        # Lista de suspeitos habituais na imagem Docker OQS
        possible_paths = [
            "/usr/local/lib64/ossl-modules",
            "/usr/local/lib/ossl-modules",
            "/usr/local/ssl/lib/ossl-modules",
            "/usr/lib/ossl-modules"
        ]

        for path in possible_paths:
            full_path = os.path.join(path, "oqsprovider.so")
            if os.path.exists(full_path):
                return path # Achamos o vencedor!
        
        # Se não achar, tenta usar o padrão do sistema (pode falhar, mas tentamos)
        return None

    def run_cmd(self, cmd_list):
        try:
            subprocess.run(cmd_list, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            stderr_msg = e.stderr.decode('utf-8') if e.stderr else "Sem msg"
            raise RuntimeError(f"OpenSSL Falhou: {stderr_msg} | Cmd: {cmd_list}")

    def run_hybrid_encryption(self, plaintext, provider_path):
        with tempfile.TemporaryDirectory() as tmp_dir:
            
            # Montagem inteligente dos argumentos
            # Se achamos o caminho, usamos -provider-path explícito.
            # Isso ignora a variável de ambiente confusa.
            provider_args = ["-provider", "oqsprovider"]
            if provider_path:
                provider_args = ["-provider-path", provider_path] + provider_args
            
            # Adiciona o provider default
            base_args = provider_args + ["-provider", "default"]
            
            # --- 1. KEM (Kyber768) ---
            kem_alg = TARGET_ALGORITHM
            kem_priv = os.path.join(tmp_dir, "kem_priv.pem")
            kem_pub = os.path.join(tmp_dir, "kem_pub.pem")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", kem_alg, "-out", kem_priv])
            self.run_cmd(["openssl", "pkey"] + base_args + ["-in", kem_priv, "-pubout", "-out", kem_pub])
            self.run_cmd(["openssl", "pkeyutl"] + base_args + ["-encap", "-inkey", kem_priv, "-peerform", "PEM", "-peerkey", kem_pub, "-out", kem_ct, "-secret", kem_ss])

            # --- 2. Clássico (X25519) ---
            dh_alg = "x25519"
            dh_priv_a = os.path.join(tmp_dir, "dh_a.pem")
            dh_priv_b = os.path.join(tmp_dir, "dh_b.pem")
            dh_pub_b = os.path.join(tmp_dir, "dh_pub_b.pem")
            dh_ss = os.path.join(tmp_dir, "dh_ss.bin")

            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_a])
            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_b])
            self.run_cmd(["openssl", "pkey"] + base_args + ["-in", dh_priv_b, "-pubout", "-out", dh_pub_b])
            self.run_cmd(["openssl", "pkeyutl"] + base_args + ["-derive", "-inkey", dh_priv_a, "-peerform", "PEM", "-peerkey", dh_pub_b, "-out", dh_ss])

            # --- 3. KDF ---
            with open(kem_ss, 'rb') as f: ss_pqc = f.read()
            with open(dh_ss, 'rb') as f: ss_dh = f.read()
            
            kdf = hashlib.sha256()
            kdf.update(ss_pqc)
            kdf.update(ss_dh)
            sym_key = kdf.digest().hex()

            # --- 4. Cifrar ---
            iv = os.urandom(12)
            pt_file = os.path.join(tmp_dir, "pt.txt")
            ct_file = os.path.join(tmp_dir, "ct.bin")
            tag_file = os.path.join(tmp_dir, "tag.bin")
            
            with open(pt_file, 'w') as f: f.write(plaintext)
            
            enc_cmd = ["openssl", "enc", "-aes-256-gcm"] + base_args + \
                      ["-K", sym_key, "-iv", iv.hex(), "-in", pt_file, "-out", ct_file, "-tag", tag_file]
            
            self.run_cmd(enc_cmd)

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
                    "pqc_kem": base64.b64encode(k_pub_b).decode('utf-8'),
                    "classic_dh": base64.b64encode(dh_pub_b).decode('utf-8')
                }
            }

if __name__ == "__main__":
    print(f"Kortana PQC Server (Auto-Discovery) rodando na porta {SERVER_PORT}")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    server.serve_forever()