FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY package.json ./
RUN npm install --omit=dev

COPY --chown=appuser:appgroup . .

RUN mkdir -p /app/data/uploads && chown -R appuser:appgroup /app/data

USER appuser
EXPOSE 3000
CMD ["npm", "start"]
