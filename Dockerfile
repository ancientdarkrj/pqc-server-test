# Imagem oficial com Criptografia Pós-Quântica
FROM openquantumsafe/oqs-ossl3

# Instalar Python
RUN apk update && apk add --no-cache python3 py3-pip

WORKDIR /app

# Copiar arquivos
COPY server_pqc.py .
COPY policy_pqc.json .

# Expor a porta
EXPOSE 8080
ENV OPENSSL_MODULES="/usr/local/lib64/ossl-modules"
ENV LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
# Rodar servidor
CMD ["python3", "-u", "server_pqc.py"]