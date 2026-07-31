FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

# src/ is bind-mounted over this by docker-compose.yml for live reload;
# copying it here too keeps `docker build` alone (no compose) runnable.
COPY tsconfig.json ./
COPY src ./src

RUN mkdir -p /app/data/keys /app/public

EXPOSE 8080

# tsx runs the TypeScript source directly and watches for changes, so the
# same image serves both local dev (with src/ bind-mounted) and a plain
# `docker compose up --build` with no bind mount.
CMD ["npx", "tsx", "watch", "src/index.ts"]
