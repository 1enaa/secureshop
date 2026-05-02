FROM node:14-alpine

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# VULN: all secrets hardcoded in image layers
ENV STRIPE_SECRET_KEY=sk_live_HARDCODED_51ABCDEF_STRIPE_KEY_xyz
ENV PAYPAL_SECRET=EHardcoded-paypal-secret-key-xyz
ENV JWT_SECRET=supersecret123
ENV DB_ENCRYPTION_KEY=db-enc-key-hardcoded-32byte!!

EXPOSE 8004
CMD ["node", "app.js"]