import os
import json
import subprocess
import base64
import hashlib
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

# Configurações da Persona Kortana: Organização e Constantes
POLICY_FILE = 'policy_pqc.json'
HOST_NAME = '0.0.0.0'
SERVER_PORT = 8080

class PQCRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        """
        Recebe texto plano, executa cifragem híbrida (PQC + Clássica) via OpenSSL CLI
        e retorna o JSON estruturado.
        """
        try:
            # 1. Ler o corpo da requisição (Texto Plano)
            content_length = int(self.headers['Content-Length'])
            plaintext = self.rfile.read(content_length).decode('utf-8')
            
            print(f"[Kortana Log] Recebido payload de {len(plaintext)} bytes. Iniciando protocolo híbrido...")

            # 2. Carregar Política
            if not os.path.exists(POLICY_FILE):
                raise FileNotFoundError("Arquivo de política não encontrado. Organização é tudo!")
            
            with open(POLICY_FILE, 'r') as f:
                policy = json.load(f)

            # 3. Executar o Fluxo Criptográfico Híbrido
            result_data = self.run_hybrid_encryption(plaintext, policy)

            # 4. Responder
            self._set_headers(200)
            self.wfile.write(json.dumps(result_data).encode('utf-8'))
            print("[Kortana Log] Resposta enviada com sucesso. :)")

        except Exception as e:
            self._set_headers(500)
            error_msg = {"error": str(e), "message": "Ops! Algo deu errado no processamento."}
            self.wfile.write(json.dumps(error_msg).encode('utf-8'))
            print(f"[Kortana Error] {e}")

    def run_hybrid_encryption(self, plaintext, policy):
        """
        Orquestra o OpenSSL via subprocess para gerar chaves, encapsular e cifrar.
        Usa arquivos temporários para garantir isolamento do processo.
        """
        # Cria um diretório temporário para manter a higiene do sistema de arquivos
        with tempfile.TemporaryDirectory() as tmp_dir:
            provider_flag = ["-provider", policy['provider'], "-provider", "default"]
            
            # --- PASSO A: Algoritmo PQC (KEM) ---
            # Como é uma simulação "Server-Side", vamos gerar um par de chaves efêmero
            # e encapsular um segredo contra ele mesmo para obter o segredo compartilhado (SS).
            # Na vida real, o cliente enviaria a chave pública, mas aqui simulamos o processo completo.
            
            kem_alg = policy['kem']
            kem_priv = os.path.join(tmp_dir, "kem_priv.pem")
            kem_pub = os.path.join(tmp_dir, "kem_pub.pem")
            kem_ct = os.path.join(tmp_dir, "kem_ct.bin")
            kem_ss = os.path.join(tmp_dir, "kem_ss.bin")

            # Gerar chaves PQC
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", kem_alg, "-out", kem_priv] + provider_flag,
                check=True, capture_output=True
            )
            # Extrair PubKey
            subprocess.run(
                ["openssl", "pkey", "-in", kem_priv, "-pubout", "-out", kem_pub] + provider_flag,
                check=True, capture_output=True
            )
            # Encapsular (Gera Ciphertext + Shared Secret)
            subprocess.run(
                ["openssl", "pkeyutl", "-encap", "-inkey", kem_priv, 
                 "-peerform", "PEM", "-peerkey", kem_pub, 
                 "-out", kem_ct, "-secret", kem_ss] + provider_flag,
                check=True, capture_output=True
            )

            # --- PASSO B: Algoritmo Clássico (DH / ECDH) ---
            # Simulamos uma troca X25519 gerando dois pares para derivar um segredo comum.
            dh_alg = policy['dh']
            dh_priv_a = os.path.join(tmp_dir, "dh_priv_a.pem") # "Servidor"
            dh_priv_b = os.path.join(tmp_dir, "dh_priv_b.pem") # "Cliente simulado"
            dh_pub_b = os.path.join(tmp_dir, "dh_pub_b.pem")
            dh_ss = os.path.join(tmp_dir, "dh_ss.bin")

            # Gerar par A
            subprocess.run(["openssl", "genpkey", "-algorithm", dh_alg, "-out", dh_priv_a], check=True)
            # Gerar par B
            subprocess.run(["openssl", "genpkey", "-algorithm", dh_alg, "-out", dh_priv_b], check=True)
            subprocess.run(["openssl", "pkey", "-in", dh_priv_b, "-pubout", "-out", dh_pub_b], check=True)
            
            # Derivar Segredo Clássico (ECDH)
            subprocess.run(
                ["openssl", "pkeyutl", "-derive", "-inkey", dh_priv_a, 
                 "-peerform", "PEM", "-peerkey", dh_pub_b, "-out", dh_ss],
                check=True
            )

            # --- PASSO C: KDF (Combinação dos Segredos) ---
            # Lemos os binários gerados
            with open(kem_ss, 'rb') as f: ss_pqc_bytes = f.read()
            with open(dh_ss, 'rb') as f: ss_classic_bytes = f.read()

            # KDF Simples: SHA256( PQC_SS || Classic_SS )
            # Isso garante que se um algoritmo quebrar, o outro ainda protege a chave (propriedade híbrida).
            kdf = hashlib.sha256()
            kdf.update(ss_pqc_bytes)
            kdf.update(ss_classic_bytes)
            symmetric_key = kdf.digest() # 32 bytes (256 bits)
            symmetric_key_hex = symmetric_key.hex()

            # --- PASSO D: Cifragem Simétrica (AES-GCM) ---
            # Gerar IV aleatório (12 bytes para GCM)
            iv = os.urandom(12)
            iv_hex = iv.hex()
            
            pt_file = os.path.join(tmp_dir, "plaintext.txt")
            ct_file = os.path.join(tmp_dir, "ciphertext.bin")
            tag_file = os.path.join(tmp_dir, "tag.bin") # OpenSSL 3 suporta saída de tag separada

            with open(pt_file, 'w') as f: f.write(plaintext)

            # Comando OpenSSL enc
            # Nota: -K e -iv esperam hex strings
            cmd_enc = [
                "openssl", "enc", "-" + policy['symmetric'],
                "-K", symmetric_key_hex,
                "-iv", iv_hex,
                "-in", pt_file,
                "-out", ct_file,
                "-tag", tag_file # Flag crucial para GCM no OpenSSL moderno
            ]
            
            subprocess.run(cmd_enc, check=True, capture_output=True)

            # --- Preparar Resposta ---
            with open(ct_file, 'rb') as f: ct_bytes = f.read()
            with open(tag_file, 'rb') as f: tag_bytes = f.read()
            with open(kem_ct, 'rb') as f: kem_ct_bytes = f.read()
            with open(kem_pub, 'rb') as f: kem_pub_bytes = f.read()
            with open(dh_pub_b, 'rb') as f: dh_pub_bytes = f.read()

            # Concatenamos a Tag GCM ao final do Ciphertext (padrão comum)
            final_ciphertext = ct_bytes + tag_bytes

            return {
                "ciphertext": base64.b64encode(final_ciphertext).decode('utf-8'),
                "nonce": base64.b64encode(iv).decode('utf-8'),
                "kem_ciphertext": base64.b64encode(kem_ct_bytes).decode('utf-8'),
                "public_keys": {
                    "pqc_kem": base64.b64encode(kem_pub_bytes).decode('utf-8'),
                    "classic_dh": base64.b64encode(dh_pub_bytes).decode('utf-8')
                }
            }

if __name__ == "__main__":
    print(f"🌟 Kortana Server v1.0 (Híbrido PQC) rodando em {HOST_NAME}:{SERVER_PORT}")
    print(f"🔧 Carregando provedor OpenSSL: oqsprovider")
    server = HTTPServer((HOST_NAME, SERVER_PORT), PQCRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDesligando servidor com carinho... Até logo!")
        server.server_close()