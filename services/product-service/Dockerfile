# VULN: outdated Node.js base image
FROM node:14-alpine

WORKDIR /app
COPY package*.json ./
# VULN: npm install without lockfile enforcement
RUN npm install
COPY . .

# VULN: hardcoded secrets in ENV
ENV API_KEY=prod-api-key-hardcoded-abc
ENV JWT_SECRET=supersecret123
ENV STRIPE_SECRET=sk_live_HARDCODED_STRIPE_KEY_XYZ
ENV NODE_ENV=development

EXPOSE 8002
CMD ["node", "app.js"]