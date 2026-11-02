# Container build for MCP registries (e.g. Glama) that build and test the server.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app /app
USER node
ENTRYPOINT ["node", "dist/cli/index.js", "mcp"]
