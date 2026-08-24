# Deployment (Docker & Kubernetes)

## Docker (single container)

### Dockerfile

```dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["python", "app.py"]
```

### Build & Run

```bash
docker build -t vap:latest .
docker run --rm -p 8000:8000 \
  -e VAP_APP_ENV=production \
  -e VAP_REQUIRE_HTTPS=false \
  vap:latest
```

## Docker Compose (con Redis)

```yaml
version: "3.9"
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      VAP_API_CACHE_ENABLED: "true"
      VAP_API_CACHE_REDIS_URL: "redis://redis:6379/0"
      VAP_REQUIRE_HTTPS: "false"
    depends_on:
      - redis
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

## Kubernetes (deployment base)

> Nota: sostituisci `vap:latest` con un'immagine pubblicata nel tuo registry.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vap
spec:
  replicas: 2
  selector:
    matchLabels:
      app: vap
  template:
    metadata:
      labels:
        app: vap
    spec:
      containers:
        - name: vap
          image: vap:latest
          ports:
            - containerPort: 8000
          env:
            - name: VAP_REQUIRE_HTTPS
              value: "false"
---
apiVersion: v1
kind: Service
metadata:
  name: vap
spec:
  selector:
    app: vap
  ports:
    - port: 80
      targetPort: 8000
      protocol: TCP
  type: ClusterIP
```

## Checklist produzione

- Abilita **HTTPS** e HSTS.
- Imposta **API key** e **JWT**.
- Usa un database esterno (PostgreSQL) per alta disponibilità.
