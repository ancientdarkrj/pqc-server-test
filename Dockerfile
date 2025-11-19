# --- KORTANA ARCHITECTURE: PQC SERVER (ARMORED EDITION) ---
FROM openquantumsafe/oqs-ossl3

# Metadados
LABEL maintainer="Kortana Team"

# 1. Instalar Python e dependências básicas
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# 2. CRUCIAL: Definir as variáveis de ambiente GLOBALMENTE
# O Python subprocess precisa disso para achar os .so (bibliotecas)
# Adicionamos caminhos comuns do OQS para garantir (lib e lib64)
ENV LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib64:/usr/local/ssl/lib:${LD_LIBRARY_PATH}"ENV LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib64:/usr/local/ssl/lib:${LD_LIBRARY_PATH}"
ENV OPENSSL_MODULES="/usr/local/lib/ossl-modules:/usr/local/lib64/ossl-modules:/usr/local/ssl/lib/ossl-modules"
ENV OPENSSL_MODULES="/usr/local/lib/ossl-modules:/usr/local/lib64/ossl-modules:/usr/local/ssl/lib/ossl-modules"
ENV PATH="/usr/local/bin:/usr/local/ssl/bin:${PATH}"

# 3. Configuração do App
WORKDIR /app

# 4. Copiar os arquivos
COPY server_pqc.py .
COPY policy_pqc.json .

# 5. Expor porta
EXPOSE 8080

# 6. Rodar servidor
# Usamos 'sh -c' para garantir que o shell propague as variáveis, por precaução.
CMD ["sh", "-c", "python3 -u server_pqc.py"]