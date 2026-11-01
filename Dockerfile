# AttackStory: engine + API + UI in one image.   docker compose up --build   →   http://localhost:8000
# stage 1: build the React UI
FROM node:20-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# stage 2: Python engine and API
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 ATTACKSTORY_RESULTS=/app/results
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY engine engine
COPY rules rules
COPY generator generator
COPY eval eval
COPY ui ui
COPY --from=ui /ui/dist frontend/dist
RUN mkdir -p results data
EXPOSE 8000
# 0.0.0.0 inside the container; docker-compose.yml publishes it on 127.0.0.1 only
CMD ["python", "-m", "engine.api", "--host", "0.0.0.0", "--port", "8000"]
