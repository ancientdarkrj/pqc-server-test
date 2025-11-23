import os
import json
import subprocess
import base64
import hashlib
import tempfile
import shutil
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST_NAME = '0.0.0.0'
SERVER_PORT = 8080
TARGET_ALGORITHM = "kyber768"

class PQCRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        # 1. Roteamento Simples (Boas Práticas)
        if self.path != '/encrypt':
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint não encontrado. Use /encrypt"}).encode('utf-8'))
            return

        try:
            print(f"\n[Kortana] Recebendo missão em {self.path}...")
            
            # 2. Identificar o Binário
            # Como fizemos o symlink no Dockerfile, "openssl" deve bastar.
            # Mas buscamos o caminho absoluto por segurança.
            openssl_bin = shutil.which("openssl")
            if not openssl_bin:
                raise RuntimeError("Binário openssl não encontrado no PATH!")
            
            print(f"[Kortana] Usando binário: {openssl_bin}")

            # 3. Configurar Ambiente (O CORRETO)
            # NÃO sobrescrevemos mais o LD_LIBRARY_PATH. Confiamos no Dockerfile!
            # Apenas copiamos o ambiente atual do sistema.
            custom_env = os.environ.copy()

            # 4. Ler e Parsear JSON (Fundamental para APIs REST)
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0:
                raise ValueError("Payload vazio")
            
            raw_body = self.rfile.read(content_length).decode('utf-8')
            
            try:
                payload = json.loads(raw_body)
                # Aceita tanto 'data' quanto 'message'
                plaintext = payload.get('data') or payload.get('message')
                if not plaintext:
                    raise ValueError("JSON deve conter campo 'data' ou 'message'")
            except json.JSONDecodeError:
                # Fallback: Se não for JSON, usa o texto puro (compatibilidade)
                plaintext = raw_body

            # 5. Executar
            result = self.run_hybrid_encryption(plaintext, openssl_bin, custom_env)

            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            print("[Kortana] SUCESSO TOTAL! 🥂")

        except Exception as e:
            print(f"[Erro Fatal] {e}")
            self._set_headers(400) # Bad Request
            # Retorna o erro detalhado para você ver no curl
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def run_cmd(self, cmd_list, env_config):
        try:
            subprocess.run(cmd_list, check=True, capture_output=True, env=env_config)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode('utf-8') if e.stderr else "Sem msg"
            # O print ajuda a ver o erro no log do container
            print(f"CMD FALHOU: {stderr}")
            raise RuntimeError(f"OpenSSL Error: {stderr}")

    def run_hybrid_encryption(self, plaintext, openssl_bin, env):
        with tempfile.TemporaryDirectory() as tmp_dir:
            
            # Argumentos Base - APENAS o provider, sem caminhos loucos
            # O Dockerfile "Takeover" já configurou onde os módulos estão.
            base_args = ["-provider", "oqsprovider", "-provider", "default"]
            
            # --- 1. KEM (Kyber) ---
            kem_priv = os.path.join(tmp_dir, "kem_priv.der") 
            kem_pub = os.path.join(tmp_dir, "kem_pub.der")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            self.run_cmd([openssl_bin, "genpkey"] + base_args + ["-algorithm", TARGET_ALGORITHM, "-out", kem_priv, "-outform", "DER"], env)
            self.run_cmd([openssl_bin, "pkey"] + base_args + ["-in", kem_priv, "-inform", "DER", "-pubout", "-out", kem_pub, "-outform", "DER"], env)
            self.run_cmd([openssl_bin, "pkeyutl"] + base_args + ["-encap", "-inkey", kem_priv, "-keyform", "DER", "-peerform", "DER", "-peerkey", kem_pub, "-out", kem_ct, "-secret", kem_ss], env)

            # --- 2. Clássico (X25519) ---
            dh_alg = "x25519"
            dh_priv_a = os.path.join(tmp_dir, "da.pem")
            dh_priv_b = os.path.join(tmp_dir, "db.pem")
            dh_pub_b = os.path.join(tmp_dir, "dpb.pem")
            dh_ss = os.path.join(tmp_dir, "dss.bin")

            self.run_cmd([openssl_bin, "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_a], env)
            self.run_cmd([openssl_bin, "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_b], env)
            self.run_cmd([openssl_bin, "pkey"] + base_args + ["-in", dh_priv_b, "-pubout", "-out", dh_pub_b], env)
            self.run_cmd([openssl_bin, "pkeyutl"] + base_args + ["-derive", "-inkey", dh_priv_a, "-peerform", "PEM", "-peerkey", dh_pub_b, "-out", dh_ss], env)

            # --- 3. KDF ---
            with open(kem_ss, 'rb') as f: kss = f.read()
            with open(dh_ss, 'rb') as f: dss = f.read()
            kdf = hashlib.sha256()
            kdf.update(kss)
            kdf.update(dss)
            sym_key = kdf.digest().hex()

            # --- 4. Cifragem ---
            iv = os.urandom(12)
            pt_file = os.path.join(tmp_dir, "pt.txt")
            ct_file = os.path.join(tmp_dir, "ct.bin")
            tag_file = os.path.join(tmp_dir, "tag.bin")
            
            # Escreve o plaintext normalizado
            with open(pt_file, 'w') as f: f.write(plaintext)

            self.run_cmd([openssl_bin, "enc", "-aes-256-gcm"] + base_args + ["-K", sym_key, "-iv", iv.hex(), "-in", pt_file, "-out", ct_file, "-tag", tag_file], env)

            with open(ct_file, 'rb') as f: ct = f.read()
            with open(tag_file, 'rb') as f: tag = f.read()
            with open(kem_ct, 'rb') as f: kct = f.read()
            with open(kem_pub, 'rb') as f: kpub = f.read()
            with open(dh_pub_b, 'rb') as f: dpub = f.read()

            return {
                "ciphertext": base64.b64encode(ct + tag).decode('utf-8'),
                "nonce": base64.b64encode(iv).decode('utf-8'),
                "kem_ciphertext": base64.b64encode(kct).decode('utf-8'),
                "public_keys": {
                    "pqc": base64.b64encode(kpub).decode('utf-8'),
                    "classic": base64.b64encode(dpub).decode('utf-8')
                },
                "status": "encrypted_successfully"
            }

if __name__ == "__main__":
    print(f"Kortana PQC Server (Production Mode) rodando na porta {SERVER_PORT}")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    server.serve_forever()