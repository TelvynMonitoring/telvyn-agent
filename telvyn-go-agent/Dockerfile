FROM golang:1.26-alpine
RUN apk add --no-cache git make bash
ARG OTELC_REVISION=2b6d03bb6752ea528f6c67bbb89b9682d645fabe
RUN git clone https://github.com/open-telemetry/opentelemetry-go-compile-instrumentation.git /opt/otelc \
    && cd /opt/otelc && git checkout "$OTELC_REVISION" \
    && make package && go build -o /usr/local/bin/otelc ./tool/cmd/otelc
COPY telvyn-go-agent /opt/telvyn/go
RUN chmod +x /opt/telvyn/go/compile/telvyn-go \
    && ln -s /opt/telvyn/go/compile/telvyn-go /usr/local/bin/telvyn-go
WORKDIR /app
ENTRYPOINT ["telvyn-go"]
