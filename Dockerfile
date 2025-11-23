# --- KORTANA ARCHITECTURE: PQC SERVER (FIXED PATHS) ---
FROM openquantumsafe/oqs-ossl3

# Metadados
LABEL maintainer="Kortana Team"

# 1. Instalar Python e dependências básicas
# O Alpine precisa do bash e pip para rodar seus scripts confortavelmente
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# 2. A CORREÇÃO MESTRA (Baseada nos fatos do 'find' e 'ldd')
# -----------------------------------------------------------
# Onde estão as bibliotecas compartilhadas (.so)?
# Adicionamos /opt/openssl/lib (onde o ldd achou a libcrypto)
ENV LD_LIBRARY_PATH="/opt/openssl/lib:/opt/openssl/lib64:${LD_LIBRARY_PATH}"

# Onde estão os módulos do OpenSSL (o provider oqs)?
# Adicionamos o caminho exato que o 'find' nos mostrou.
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"

# Adicionamos o binário do openssl ao PATH para facilitar debugging
ENV PATH="/opt/openssl/bin:${PATH}"
# -----------------------------------------------------------

# 3. Configuração do App
WORKDIR /app

# 4. Copiar os arquivos
COPY server_pqc.py .
COPY policy_pqc.json .

# 5. Expor porta
# (Nota: No seu curl você usou 9000, aqui está 8080.
# Certifique-se de alinhar isso no docker run -p 9000:8080)
EXPOSE 8080

# 6. Rodar servidor
# O '-u' no Python é ótimo, evita buffer de log e mostra erros na hora.
CMD ["sh", "-c", "python3 -u server_pqc.py"]