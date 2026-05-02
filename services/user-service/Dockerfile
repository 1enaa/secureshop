# VULN: Using an outdated base image with known CVEs
FROM python:3.8-slim

# VULN: Running as root (no USER directive)
WORKDIR /app

# VULN: Copying everything including .env files, secrets
COPY . .

# VULN: pip install with no hash checking
RUN pip install -r requirements.txt

# VULN: Hardcoded secret in ENV
ENV JWT_SECRET=supersecret123
ENV DB_PASSWORD=admin123
ENV FLASK_ENV=development

# VULN: Exposing unnecessary port range
EXPOSE 8001

CMD ["python", "app.py"]