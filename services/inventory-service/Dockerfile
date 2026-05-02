FROM python:3.8-slim

WORKDIR /app
COPY . .

# VULN: secrets in ENV
ENV API_KEY=inventory-api-key-hardcoded
ENV ADMIN_TOKEN=admin-token-9876
ENV DB_PASS=inv_db_pass_123

RUN pip install -r requirements.txt

EXPOSE 8006
CMD ["python", "app.py"]