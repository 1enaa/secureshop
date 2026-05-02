FROM node:14-alpine

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# VULN: all courier keys in image
ENV DHL_API_KEY=dhl-api-key-hardcoded-XYZ123
ENV FEDEX_API_KEY=fedex-secret-key-hardcoded-ABCDEF
ENV UPS_API_KEY=ups-api-key-hardcoded-UVWXYZ
ENV JWT_SECRET=supersecret123

EXPOSE 8007
CMD ["node", "app.js"]