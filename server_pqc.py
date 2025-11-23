import os
import json
import subprocess
import base64
import hashlib
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST_NAME = '0.0.0.0'
SERVER_PORT = 8080

# ALGORITMO
# Se Kyber continuar falhando, troque aqui por 'frodo640aes'
TARGET_ALGORITHM = "kyber768"

class PQCRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        try:
            print(f"\n[Kortana] Recebendo missão...")
            
            # 1. Identificar o Binário CORRETO (OQS)
            # A imagem OQS instala o customizado em /usr/local/bin
            openssl_bin = "/usr/local/bin/openssl"
            if not os.path.exists(openssl_bin):
                # Fallback se mudaram a imagem
                openssl_bin = "openssl"
            
            print(f"[Kortana] Usando binário: {openssl_bin}")

            # 2. Configurar Ambiente na força bruta
            # Apontamos para onde as libs costumam estar na imagem OQS
            custom_env = os.environ.copy()
            custom_env["LD_LIBRARY_PATH"] = "/usr/local/lib:/usr/local/lib64:/usr/local/ssl/lib"
            # Forçamos o arquivo de configuração para carregar os defaults
            custom_env["OPENSSL_CONF"] = "/usr/local/ssl/openssl.cnf"

            # 3. Ler Payload
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0: raise ValueError("Payload vazio")
            plaintext = self.rfile.read(content_length).decode('utf-8')

            # 4. Executar
            result = self.run_hybrid_encryption(plaintext, openssl_bin, custom_env)

            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            print("[Kortana] SUCESSO TOTAL! 🥂")

        except Exception as e:
            print(f"[Erro] {e}")
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def run_cmd(self, cmd_list, env_config):
        try:
            # Capture_output=True pega o erro se der pau
            subprocess.run(cmd_list, check=True, capture_output=True, env=env_config)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode('utf-8') if e.stderr else "Sem msg"
            raise RuntimeError(f"OpenSSL Falhou: {stderr} | Cmd: {cmd_list}")

    def run_hybrid_encryption(self, plaintext, openssl_bin, env):
        with tempfile.TemporaryDirectory() as tmp_dir:
            
            # Argumentos Base
            # Nota: Não usamos mais -provider-path pois o LD_LIBRARY_PATH deve resolver
            # Se der erro de provider load, voltamos com ele.
            base_args = ["-provider", "oqsprovider", "-provider", "default"]
            
            # --- 1. KEM (Kyber) ---
            # TRUQUE DE MESTRA: Usar formato DER (Binário) em vez de PEM (Texto)
            # O erro "No encoders found" geralmente acontece na conversão para texto.
            # Binário é nativo e não precisa de encoder complexo.
            kem_priv = os.path.join(tmp_dir, "kem_priv.der") 
            kem_pub = os.path.join(tmp_dir, "kem_pub.der")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            # Geração da chave privada (formato DER)
            self.run_cmd([openssl_bin, "genpkey"] + base_args + ["-algorithm", TARGET_ALGORITHM, "-out", kem_priv, "-outform", "DER"], env)
            
            # Extração da pública (formato DER)
            self.run_cmd([openssl_bin, "pkey"] + base_args + ["-in", kem_priv, "-inform", "DER", "-pubout", "-out", kem_pub, "-outform", "DER"], env)
            
            # Encapsulamento (KEM)
            self.run_cmd([openssl_bin, "pkeyutl"] + base_args + ["-encap", "-inkey", kem_priv, "-keyform", "DER", "-peerform", "DER", "-peerkey", kem_pub, "-out", kem_ct, "-secret", kem_ss], env)

            # --- 2. Clássico (X25519) ---
            dh_alg = "x25519"
            dh_priv_a = os.path.join(tmp_dir, "da.pem")
            dh_priv_b = os.path.join(tmp_dir, "db.pem")
            dh_pub_b = os.path.join(tmp_dir, "dpb.pem")
            dh_ss = os.path.join(tmp_dir, "dss.bin")

            # Clássico funciona bem com PEM, mantemos padrão
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
                }
            }

if __name__ == "__main__":
    print(f"Kortana PQC Server (DER Bypass Mode) rodando na porta {SERVER_PORT}")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    server.serve_forever()