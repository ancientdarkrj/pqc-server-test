import os
import json
import subprocess
import base64
import hashlib
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST_NAME = '0.0.0.0'
SERVER_PORT = 8080

# Vamos tentar Kyber. Se falhar, o script vai tentar achar o erro de configuração.
TARGET_ALGORITHM = "kyber768"

class PQCRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        try:
            print(f"\n[Kortana] Recebendo missão...")

            # --- FASE 1: Descobrir a Configuração Certa ---
            # Não vamos mais procurar arquivo. Vamos testar qual CAMINHO funciona.
            working_env = self.find_working_configuration()
            
            if not working_env:
                raise RuntimeError("FATAL: Nenhuma pasta de módulos fez o OpenSSL funcionar. O container está vazio?")

            # --- FASE 2: Leitura do Payload ---
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0: raise ValueError("Payload vazio")
            plaintext = self.rfile.read(content_length).decode('utf-8')

            # --- FASE 3: Execução ---
            result = self.run_hybrid_encryption(plaintext, working_env)

            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            print("[Kortana] Missão Cumprida! 🥂")

        except Exception as e:
            print(f"[Erro] {e}")
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def find_working_configuration(self):
        """
        Testa vários caminhos comuns para a variável OPENSSL_MODULES.
        O primeiro que permitir carregar o 'oqsprovider' ganha.
        """
        # Lista de suspeitos baseada na imagem oficial OQS e Linux padrão
        candidate_paths = [
            "/usr/local/lib64/ossl-modules",
            "/usr/local/lib/ossl-modules",
            "/usr/lib/ossl-modules",
            "/usr/lib64/ossl-modules",
            "/usr/local/ssl/lib/ossl-modules",
            "/opt/oqssa/lib/ossl-modules", # Algumas builds usam /opt
            None # Tenta sem nada (padrão do sistema)
        ]

        print("[Kortana Debug] Testando chaves de configuração...")

        for path in candidate_paths:
            env_test = os.environ.copy()
            
            # Configura o teste
            if path:
                env_test["OPENSSL_MODULES"] = path
            elif "OPENSSL_MODULES" in env_test:
                del env_test["OPENSSL_MODULES"] # Testar limpo

            # Tenta listar o provider OQS
            try:
                # O comando 'openssl list -providers -provider oqsprovider' retorna sucesso se carregar
                cmd = ["openssl", "list", "-providers", "-provider", "oqsprovider", "-provider", "default"]
                result = subprocess.run(cmd, capture_output=True, env=env_test)
                
                if result.returncode == 0:
                    print(f"[Kortana Debug] SUCESSO com path: {path if path else 'PADRAO'}")
                    return env_test # Achamos a chave certa!
            except Exception:
                continue
        
        return None

    def run_cmd(self, cmd_list, env_config):
        try:
            subprocess.run(cmd_list, check=True, capture_output=True, env=env_config)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode('utf-8') if e.stderr else "Sem msg"
            raise RuntimeError(f"OpenSSL Falhou: {stderr} | Cmd: {cmd_list}")

    def run_hybrid_encryption(self, plaintext, env_config):
        with tempfile.TemporaryDirectory() as tmp_dir:
            
            # Argumentos base (agora sabemos que o env_config garante o carregamento)
            base_args = ["-provider", "oqsprovider", "-provider", "default"]
            
            # 1. KEM (Kyber)
            kem_priv = os.path.join(tmp_dir, "kem_priv.pem")
            kem_pub = os.path.join(tmp_dir, "kem_pub.pem")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", TARGET_ALGORITHM, "-out", kem_priv], env_config)
            self.run_cmd(["openssl", "pkey"] + base_args + ["-in", kem_priv, "-pubout", "-out", kem_pub], env_config)
            self.run_cmd(["openssl", "pkeyutl"] + base_args + ["-encap", "-inkey", kem_priv, "-peerform", "PEM", "-peerkey", kem_pub, "-out", kem_ct, "-secret", kem_ss], env_config)

            # 2. Clássico (X25519)
            dh_alg = "x25519"
            dh_priv_a = os.path.join(tmp_dir, "da.pem")
            dh_priv_b = os.path.join(tmp_dir, "db.pem")
            dh_pub_b = os.path.join(tmp_dir, "dpb.pem")
            dh_ss = os.path.join(tmp_dir, "dss.bin")

            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_a], env_config)
            self.run_cmd(["openssl", "genpkey"] + base_args + ["-algorithm", dh_alg, "-out", dh_priv_b], env_config)
            self.run_cmd(["openssl", "pkey"] + base_args + ["-in", dh_priv_b, "-pubout", "-out", dh_pub_b], env_config)
            self.run_cmd(["openssl", "pkeyutl"] + base_args + ["-derive", "-inkey", dh_priv_a, "-peerform", "PEM", "-peerkey", dh_pub_b, "-out", dh_ss], env_config)

            # 3. KDF
            with open(kem_ss, 'rb') as f: kss = f.read()
            with open(dh_ss, 'rb') as f: dss = f.read()
            kdf = hashlib.sha256()
            kdf.update(kss)
            kdf.update(dss)
            sym_key = kdf.digest().hex()

            # 4. Cifragem
            iv = os.urandom(12)
            pt_file = os.path.join(tmp_dir, "pt.txt")
            ct_file = os.path.join(tmp_dir, "ct.bin")
            tag_file = os.path.join(tmp_dir, "tag.bin")
            with open(pt_file, 'w') as f: f.write(plaintext)

            self.run_cmd(["openssl", "enc", "-aes-256-gcm"] + base_args + ["-K", sym_key, "-iv", iv.hex(), "-in", pt_file, "-out", ct_file, "-tag", tag_file], env_config)

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
    print(f"Kortana PQC Server (Brute Force Config) rodando na porta {SERVER_PORT}")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    server.serve_forever()