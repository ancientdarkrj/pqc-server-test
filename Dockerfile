# --- KORTANA ARCHITECTURE: PQC SERVER (THE TAKEOVER) ---
FROM openquantumsafe/oqs-ossl3

LABEL maintainer="Kortana Team"

# 1. Instalar Python (Isso traz o openssl do sistema 'intruso')
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# 2. O GOLPE DE ESTADO (SUBSTITUIÇÃO DE BINÁRIO) ⚔️
# Removemos/Renomeamos o openssl do Alpine para ele não atrapalhar
# E criamos um link do nosso openssl OQS para o local padrão
RUN mv /usr/bin/openssl /usr/bin/openssl.alpine || true && \
    ln -s /opt/openssl/bin/openssl /usr/bin/openssl

# 3. AJUSTE DE AMBIENTE (FINE TUNING) 🎛️
# Como o default provider é embutido, NÃO precisamos apontar path para ele.
# Apontamos APENAS para o módulo extra (OQS).
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"

# Garantimos que as bibliotecas certas sejam carregadas
ENV LD_LIBRARY_PATH="/opt/openssl/lib:/opt/openssl/lib64:${LD_LIBRARY_PATH}"

# Forçamos o uso da configuração do OQS (caso exista)
ENV OPENSSL_CONF="/opt/openssl/ssl/openssl.cnf"

# Adiciona ao PATH (Redundância de segurança)
ENV PATH="/opt/openssl/bin:${PATH}"

# 4. Configuração do App
WORKDIR /app
COPY server_pqc.py .
COPY policy_pqc.json .

EXPOSE 8080

# 5. Start
CMD ["sh", "-c", "python3 -u server_pqc.py"]