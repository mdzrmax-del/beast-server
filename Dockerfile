FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash git python3 python3-pip python3-venv build-essential cmake zip unzip curl wget jq ca-certificates default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 beast && mkdir -p /data/work && chown -R beast /data
USER beast
WORKDIR /app
COPY server.js .
ENV PORT=8080 WORK_ROOT=/data/work
EXPOSE 8080
CMD ["node", "server.js"]
