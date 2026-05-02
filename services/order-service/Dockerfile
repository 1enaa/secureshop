FROM python:3.8-slim

WORKDIR /app
COPY . .

# VULN: hardcoded credentials in build args/env
ENV SECRET_KEY=order-secret-key-123
ENV DB_PASSWORD=orderdb_pass
ENV PAYMENT_API_KEY=pk_live_HARDCODED_KEY_12345

RUN pip install -r requirements.txt

EXPOSE 8003
CMD ["python", "app.py"]