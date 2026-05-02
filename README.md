# SecureShop — DevSecOps Workshop 3

A lightweight e-commerce platform built on microservices, used as the target for a complete DevSecOps pipeline.

## System Architecture

```
External Clients  (Browser / Mobile / REST)
        │  HTTPS
        ▼
 API Gateway  (Nginx :80)
        │
        ├── user-service          :8001  Python / FastAPI   — Auth, JWT, profiles
        ├── product-service       :8002  Node.js / Express  — Catalogue, search
        ├── order-service         :8003  Python / FastAPI   — Cart, order lifecycle
        ├── payment-service       :8004  Node.js / Express  — Payments, transactions
        ├── notification-service  :8005  Python / FastAPI   — Email/SMS + RabbitMQ
        ├── inventory-service     :8006  Python / FastAPI   — Stock, reserve, release
        └── delivery-service      :8007  Node.js / Express  — Shipments, tracking
                                              │
                                         RabbitMQ :5672
                                   (order → notification events)
```

## Quick Start

```bash
# 1. Configure secrets
cp .env.example .env
# Edit .env — set JWT_SECRET, RABBITMQ_USER, RABBITMQ_PASS

# 2. Build and start
docker compose up --build

# 3. Verify gateway
curl http://localhost/health

# 4. Register a user
curl -X POST http://localhost/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"SecureP@ss1!"}'

# 5. Login and get JWT
curl -X POST http://localhost/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"SecureP@ss1!"}'

# 6. Browse products
curl http://localhost/api/v1/products
```

## Service Endpoints Summary

| Service      | Base URL                    | Key Endpoints                          |
|--------------|-----------------------------|----------------------------------------|
| User         | `/api/v1/`                  | `POST /register` `POST /login` `GET /profile` |
| Product      | `/api/v1/products`          | `GET` `POST` `PUT /products/:id`       |
| Order        | `/api/v1/orders`            | `POST /orders` `GET /orders/:id`       |
| Payment      | `/api/v1/payments`          | `POST /payments` `GET /payments/:id`   |
| Notification | `/api/v1/notifications`     | `POST /notify` `GET /notifications`    |
| Inventory    | `/api/v1/inventory`         | `GET /stock/:id` `POST /reserve`       |
| Delivery     | `/api/v1/shipments` `/api/v1/track` | `POST /shipments` `GET /track/:num` |

## Repository Structure

```
secureshop/
├── api-gateway/                  # Nginx reverse proxy + rate limiting
├── services/
│   ├── user-service/             # Python / FastAPI
│   ├── product-service/          # Node.js / Express
│   ├── order-service/            # Python / FastAPI
│   ├── payment-service/          # Node.js / Express
│   ├── notification-service/     # Python / FastAPI
│   ├── inventory-service/        # Python / FastAPI
│   └── delivery-service/         # Node.js / Express
├── .github/workflows/
│   └── devsecops.yml             # Full CI/CD pipeline (7 stages)
├── security/
│   ├── sast/                     # Bandit config, Semgrep rules
│   ├── sca/                      # Trivy ignore list
│   ├── dast/                     # ZAP context files
│   └── reports/                  # Generated scan outputs (git-ignored)
├── scripts/
│   ├── run-sast.sh
│   ├── run-sca.sh
│   ├── run-secrets.sh
│   └── run-container-scan.sh
├── .zap/rules.tsv
├── docker-compose.yml
├── .env.example
└── README.md
```

## DevSecOps Pipeline

| Stage | Tool | Target |
|-------|------|--------|
| SAST  | Bandit | Python services |
| SAST  | Semgrep | Node.js services |
| SCA   | Trivy (fs) | All dependency files |
| Secrets | Gitleaks | Full git history |
| Build | Docker Compose | All 7 services |
| Container Scan | Trivy (image) | Each built image |
| IaC   | Checkov | Dockerfiles + docker-compose |
| DAST  | OWASP ZAP | Running stack on localhost |

All SARIF results are uploaded to **GitHub Security → Code Scanning**.

## Security Posture

- Non-root user in every container
- Secrets only via environment variables (`.env` is git-ignored)
- Nginx enforces security headers and 100 req/min rate limiting
- JWT expiry: 24 h; secret injected at runtime
