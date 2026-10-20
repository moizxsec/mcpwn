# mcpwn — multi-stage build (zero runtime deps: node:* only).
#
#   docker build -t mcpwn .
#   docker run --rm -i mcpwn --version
#   docker run --rm -i mcpwn scan --http https://mcp.example.com/mcp
#   # wrap a stdio server that lives in the image/mount:
#   docker run --rm -i -v "$PWD":/work -w /work mcpwn -- node ./my-server.js
#
# stdin/stdout are the MCP channel, so run with -i (and no -t) when proxying.

# ---- build stage: compile TypeScript -> dist/ ----
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build

# ---- runtime stage: dist + bundled data, no dev deps ----
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
# mcpwn ships zero runtime dependencies, so this installs nothing — it just keeps
# node_modules honest if a runtime dep is ever added.
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
# Bundled data the CLI reads at runtime (payload libraries, template gallery,
# schemas, demo/DVMCP servers) resolves relative to the package root.
COPY payloads ./payloads
COPY templates ./templates
COPY schema ./schema
COPY examples ./examples
COPY README.md ./
ENTRYPOINT ["node", "dist/cli.js"]
