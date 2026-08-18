# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DEFENDER_URL=http://defender:8080
COPY --from=build /app /app
EXPOSE 3000
CMD ["npx", "vite", "preview", "--host", "0.0.0.0", "--port", "3000"]
