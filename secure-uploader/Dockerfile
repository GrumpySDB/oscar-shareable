FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -g 911 -S appgroup && adduser -u 911 -S appuser -G appgroup
RUN apk add --no-cache openssl

COPY package.json ./
RUN npm install --omit=dev

COPY --chown=appuser:appgroup . .

RUN mkdir -p /app/data/uploads /app/certs \
  && openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
    -keyout /app/certs/key.pem \
    -out /app/certs/cert.pem \
    -days 3650 \
    -subj "/CN=localhost" \
  && chown -R appuser:appgroup /app/data /app/certs \
  && chmod 600 /app/certs/key.pem \
  && chmod 644 /app/certs/cert.pem

USER appuser
EXPOSE 3000 3443
CMD ["npm", "start"]
