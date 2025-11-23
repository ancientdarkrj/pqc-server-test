# --- KORTANA ARCHITECTURE: PQC SERVER (BINARY TAKEOVER EDITION) ---
FROM openquantumsafe/oqs-ossl3

# Metadados para rastreabilidade
LABEL maintainer="Kortana Team" \
      description="Servidor Python com OpenSSL Pós-Quântico (OQS) forçado sobre o sistema"

# 1. Instalação de Dependências
# O Alpine vai instalar o openssl padrão como dependência do python3.
# Nós permitimos isso agora para corrigir logo abaixo.
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# 2. O GOLPE DE ESTADO (BINARY TAKEOVER) ⚔️
# ---------------------------------------------------------------------
# O problema anterior era: O Python chamava /usr/bin/openssl (Alpine padrão),
# mas nós passávamos configurações do OQS. Resultado: "No encoders found".
# SOLUÇÃO: Movemos o binário padrão e colocamos um link simbólico para o OQS.
RUN mv /usr/bin/openssl /usr/bin/openssl.alpine || true && \
    ln -s /opt/openssl/bin/openssl /usr/bin/openssl

# 3. CONFIGURAÇÃO DE AMBIENTE (Focada na Realidade /opt) 🗺️
# ---------------------------------------------------------------------
# Onde estão as bibliotecas .so? (libcrypto, libssl)
# Adicionamos ambos os caminhos para garantir compatibilidade.
ENV LD_LIBRARY_PATH="/opt/openssl/lib:/opt/openssl/lib64:${LD_LIBRARY_PATH}"

# Onde está o módulo Kyber/Dilithium?
# Apontamos EXATAMENTE para onde o comando 'find' mostrou.
# NOTA: Não precisamos apontar o 'default', pois o binário OQS já o tem embutido.
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"

# Configuração padrão do OpenSSL OQS
ENV OPENSSL_CONF="/opt/openssl/ssl/openssl.cnf"

# Garantia extra: Coloca o binário OQS no início do PATH
ENV PATH="/opt/openssl/bin:${PATH}"

# 4. Configuração da Aplicação
WORKDIR /app

# Copia os artefatos do projeto
COPY server_pqc.py .
COPY policy_pqc.json .

# 5. Exposição de Porta
# Lembre-se de mapear 9000:8080 no Coolify
EXPOSE 8080

# 6. Execução
# -u: Unbuffered (logs aparecem instantaneamente, vital para debug)
CMD ["sh", "-c", "python3 -u server_pqc.py"]