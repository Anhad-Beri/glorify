FROM python:3.12-slim

# --- Node 22 (same version setup/reprovision.sh installs on the Steel Computer) ---
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsL -o /tmp/node.tar.gz https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.gz && \
    tar -xzf /tmp/node.tar.gz -C /opt && \
    ln -s /opt/node-v22.23.2-linux-x64/bin/node /usr/local/bin/node && \
    ln -s /opt/node-v22.23.2-linux-x64/bin/npm /usr/local/bin/npm && \
    rm /tmp/node.tar.gz && \
    rm -rf /var/lib/apt/lists/*

# --- Steel CLI (webapp/server.py shells out to this for "steel computer exec") ---
RUN curl -fsS https://setup.steel.dev | sh
ENV PATH="/root/.steel/bin:${PATH}"

WORKDIR /app

# Python deps first so this layer only rebuilds when requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x railway-start.sh

EXPOSE 8000
CMD ["./railway-start.sh"]
