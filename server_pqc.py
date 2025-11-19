import os
import json
import subprocess
import base64
import hashlib
import tempfile
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
        try:
            # --- FASE 1: DIAGNÓSTICO ---
            print(f"\n[Kortana] Iniciando caçada ao provider...")
            
            # Vamos procurar onde o arquivo realmente está
            provider_full_path = self.hunt_for_provider()
            
            if not provider_full_path:
                raise RuntimeError("FATAL: O arquivo 'oqsprovider.so' não foi encontrado em lugar nenhum do sistema!")
            
            # Extrair apenas o diretório (ex: /usr/local/lib64/ossl-modules)
            provider_dir = os.path.dirname(provider_full_path)
            print(f"[Kortana] Provider localizado em: {provider_dir}")

            # --- FASE 2: EXECUÇÃO ---
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0: raise ValueError("Payload vazio")
            plaintext = self.rfile.read(content_length).decode('utf-8')

            result = self.run_hybrid_encryption(plaintext, provider_dir)

            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode('utf-8'))

        except Exception as e:
            print(f"[Erro] {e}")
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def hunt_for_provider(self):
        """Roda um comando 'find' no Linux para achar o arquivo, custe o que custar."""
        try:
            # Procura a partir da raiz /usr (mais rápido que /)
            cmd = ["find", "/usr", "-name", "oqsprovider.so"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            paths = result.stdout.strip().split('\n')
            # Pega o primeiro que encontrar que não seja vazio
            for p in paths:
                if p and p.endswith(".so"):
                    return p
            return None
        except Exception as e:
            print(f"Erro na busca: {e}")
            return None

    def run_cmd(self, cmd_list, clean_env):
        """Roda comando com ambiente limpo para evitar conflito de variáveis"""
        try:
            # Passamos o 'clean_env' aqui! Isso é o pulo do gato.
            subprocess.run(cmd_list, check=True, capture_output=True, env=clean_env)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode('utf-8') if e.stderr else "Sem msg"
            raise RuntimeError(f"OpenSSL Falhou: {stderr} | Cmd: {cmd_list}")

    def run_hybrid_encryption(self, plaintext, provider_path):
        with tempfile.TemporaryDirectory() as tmp_dir:
            
            # --- LIMPEZA DO AMBIENTE (CRUCIAL) ---
            # Copiamos o ambiente atual, mas REMOVEMOS a variável que causou o erro
            my_env = os.environ.copy()
            if "OPENSSL_MODULES" in my_env:
                del my_env["OPENSSL_MODULES"]
            
            # Argumentos explícitos
            # -provider-path DEVE vir antes de -provider oqsprovider
            base_args = ["-provider-path", provider_path, "-provider", "oqsprovider", "-provider", "default"]
            
            # 1. KEM (Kyber)
            kem_priv = os.path.join(tmp_dir, "kem_priv.pem")
            kem_pub = os.path.join(tmp_dir, "kem_pub.pem")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", TARGET_ALGORITHM, "-out", kem_priv], my_env)
            
            # VERIFICAÇÃO (Respondendo sua pergunta): O arquivo existe?
            if not os.path.exists(kem_priv):
                raise RuntimeError("O OpenSSL rodou sem erro, mas o arquivo .pem não apareceu! Mistério total.")

            self.run_cmd(["openssl", "pkey"] + base_args + ["-in", kem_priv, "-pubout", "-out", kem_pub], my_env)
            self.run_cmd(["openssl", "pkeyutl"] + base_args + ["-encap", "-inkey", kem_priv, "-peerform", "PEM", "-peerkey", kem_pub, "-out", kem_ct, "-secret", kem_ss], my_env)

            # 2. Clássico & Cifragem (resto do fluxo igual)
            dh_alg = "x25519"
            dh_priv_a = os.path.join(tmp_dir, "da.pem")
            dh_priv_b = os.path.join(tmp_dir, "db.pem")
            dh_pub_b = os.path.join(tmp_dir, "dpb.pem")
            dh_ss = os.path.join(tmp_dir, "dss.bin")

            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_a], my_env)
            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_b], my_env)
            self.run_cmd(["openssl", "pkey"] + base_args + ["-in", dh_priv_b, "-pubout", "-out", dh_pub_b], my_env)
            self.run_cmd(["openssl", "pkeyutl"] + base_args + ["-derive", "-inkey", dh_priv_a, "-peerform", "PEM", "-peerkey", dh_pub_b, "-out", dh_ss], my_env)

            with open(kem_ss, 'rb') as f: kss = f.read()
            with open(dh_ss, 'rb') as f: dss = f.read()
            kdf = hashlib.sha256()
            kdf.update(kss)
            kdf.update(dss)
            sym_key = kdf.digest().hex()

            iv = os.urandom(12)
            pt_file = os.path.join(tmp_dir, "pt.txt")
            ct_file = os.path.join(tmp_dir, "ct.bin")
            tag_file = os.path.join(tmp_dir, "tag.bin")
            with open(pt_file, 'w') as f: f.write(plaintext)

            self.run_cmd(["openssl", "enc", "-aes-256-gcm"] + base_args + ["-K", sym_key, "-iv", iv.hex(), "-in", pt_file, "-out", ct_file, "-tag", tag_file], my_env)

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
    print(f"Kortana PQC Server (Sniper Mode) rodando na porta {SERVER_PORT}")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    server.serve_forever()