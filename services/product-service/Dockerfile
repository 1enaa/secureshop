FROM node:20-alpine
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY package*.json ./
RUN npm ci --only=production
COPY src/ ./src/
RUN chown -R appuser:appgroup /app
USER appuser
EXPOSE 8002
CMD ["node", "src/index.js"]
