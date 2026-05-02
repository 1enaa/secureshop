FROM python:3.8-slim

WORKDIR /app
COPY . .

# VULN: credentials hardcoded in image
ENV SMTP_PASSWORD=SmtpP@ss_Hardcoded!
ENV SMTP_API_KEY=SG.hardcoded_sendgrid_api_key_xyz
ENV RABBITMQ_PASS=admin123
ENV FTP_PASS=ftp_pass_123

RUN pip install -r requirements.txt

EXPOSE 8005
CMD ["python", "app.py"]