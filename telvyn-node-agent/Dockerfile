FROM node:20-alpine AS package
WORKDIR /opt/telvyn/node
COPY telvyn-node-agent/package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY telvyn-node-agent/register.cjs telvyn-node-agent/bootstrap.cjs telvyn-node-agent/profiler.cjs telvyn-node-agent/profile-context.cjs telvyn-node-agent/routes.cjs telvyn-node-agent/security.cjs telvyn-node-agent/iast.cjs telvyn-node-agent/mariadb.cjs telvyn-node-agent/debugger.cjs telvyn-node-agent/runtime.cjs telvyn-node-agent/remote.cjs telvyn-node-agent/protection.cjs telvyn-node-agent/frameworks.cjs telvyn-node-agent/waf-rules.json telvyn-node-agent/WAF-RULES-NOTICE.md ./
COPY telvyn-node-agent/loader.mjs ./

FROM alpine:3.20
COPY --from=package /opt/telvyn/node /opt/telvyn/node
CMD ["sh", "-c", "cp -R /opt/telvyn/node/. /target/"]
