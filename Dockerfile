# Single image for all three Node services; compose selects the entrypoint.
FROM node:22-alpine AS build
WORKDIR /app

RUN corepack enable

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json tsconfig.json ./
COPY packages ./packages
COPY apps/pop ./apps/pop
COPY apps/connector ./apps/connector
COPY apps/demo-app ./apps/demo-app
# Needed only so the lockfile's workspace importers all resolve; the
# extension itself is never built here.
COPY apps/extension/package.json ./apps/extension/package.json

# Filtered install: `...` pulls in each app's workspace dependencies, so the
# extension's React/Vite toolchain never enters the image.
RUN pnpm install --frozen-lockfile \
      --filter '@ztna/pop...' \
      --filter '@ztna/connector...' \
      --filter '@ztna/demo-app...' \
 && pnpm --filter @ztna/tunnel --filter @ztna/policy build \
 && pnpm --filter @ztna/pop --filter @ztna/connector --filter @ztna/demo-app build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app ./
