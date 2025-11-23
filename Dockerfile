# --- KORTANA ARCHITECTURE: THE FORGE (COMPILE FROM SOURCE) ---
# Usamos Alpine puro para ter controle total
FROM alpine:3.20 as builder

LABEL maintainer="Kortana Team"

# 1. Instalar Ferramentas de Compilação (A Fábrica)
RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    git \
    python3 \
    linux-headers \
    perl

# 2. Preparar Diretórios
WORKDIR /build
ENV INSTALL_PREFIX="/opt/openssl"

# 3. Baixar e Compilar liboqs (A Matemática Quântica)
# Versão estável 0.10.0
RUN git clone --branch 0.10.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX -DOQS_USE_OPENSSL=OFF .. && \
    ninja && ninja install

# 4. Baixar e Compilar OpenSSL 3 (O Motor)
# Versão 3.3.0
RUN cd /build && \
    git clone --branch openssl-3.3.0 --depth 1 https://github.com/openssl/openssl.git && \
    cd openssl && \
    ./config --prefix=$INSTALL_PREFIX --openssldir=$INSTALL_PREFIX/ssl shared && \
    make -j$(nproc) && \
    make install_sw

# 5. Baixar e Compilar OQS Provider (A Ponte)
# Versão 0.6.0
RUN cd /build && \
    git clone --branch 0.6.0 --depth 1 https://github.com/open-quantum-safe/oqsprovider.git && \
    cd oqsprovider && \
    liboqs_DIR=$INSTALL_PREFIX cmake -GNinja \
        -DOPENSSL_ROOT_DIR=$INSTALL_PREFIX \
        -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
        . && \
    ninja && ninja install

# --- ESTÁGIO FINAL: A IMAGEM LEVE ---
FROM alpine:3.20

# Instala Python e dependências de runtime
RUN apk add --no-cache python3 py3-pip bash libstdc++

# Copia APENAS o que foi compilado (O resultado limpo)
COPY --from=builder /opt/openssl /opt/openssl

# Configura as Variáveis de Ambiente (O Mapa do Tesouro)
ENV PATH="/opt/openssl/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/openssl/lib:/opt/openssl/lib64:${LD_LIBRARY_PATH}"
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"
ENV OPENSSL_CONF="/opt/openssl/ssl/openssl.cnf"

# O Golpe de Estado (Link Simbólico para garantir)
RUN mv /usr/bin/openssl /usr/bin/openssl.alpine || true && \
    ln -s /opt/openssl/bin/openssl /usr/bin/openssl

# Configuração do App
WORKDIR /app
COPY server_pqc.py .
COPY policy_pqc.json .

EXPOSE 8080

CMD ["sh", "-c", "python3 -u server_pqc.py"]