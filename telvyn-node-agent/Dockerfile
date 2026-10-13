FROM node:20-alpine AS package
WORKDIR /opt/telvyn/node
COPY telvyn-node-agent/package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY telvyn-node-agent/register.cjs telvyn-node-agent/bootstrap.cjs telvyn-node-agent/profiler.cjs ./

FROM alpine:3.20
COPY --from=package /opt/telvyn/node /opt/telvyn/node
CMD ["sh", "-c", "cp -R /opt/telvyn/node/. /target/"]
