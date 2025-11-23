# --- KORTANA ARCHITECTURE: PQC SERVER (ALPINE FIX) ---
FROM openquantumsafe/oqs-ossl3

# Metadados
LABEL maintainer="Kortana Team"

# 1. Instalar dependências de sistema
# Bash é necessário para scripts e debugging; Pip para dependências Python
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# 2. CORREÇÃO DE AMBIENTE (CRÍTICO) 🚑
# -----------------------------------------------------------
# O comando 'find' no servidor revelou que as libs estão em /opt/openssl
# Precisamos dizer isso ao Linux e ao OpenSSL.

# Para o Python achar a libcrypto.so.3:
ENV LD_LIBRARY_PATH="/opt/openssl/lib:/opt/openssl/lib64:${LD_LIBRARY_PATH}"

# Para o OpenSSL achar o provider 'oqs' (Kyber, Dilithium, etc):
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"

# Adiciona binários ao PATH para facilitar (opcional)
ENV PATH="/opt/openssl/bin:${PATH}"
# -----------------------------------------------------------

# 3. Configuração do Diretório
WORKDIR /app

# 4. Copiar Código e Políticas
COPY server_pqc.py .
COPY policy_pqc.json .

# 5. Expor a porta (Mapear 9000:8080 no Coolify/Docker)
EXPOSE 8080

# 6. Start
# O flag -u garante que os logs saiam em tempo real (sem buffer)
CMD ["sh", "-c", "python3 -u server_pqc.py"]