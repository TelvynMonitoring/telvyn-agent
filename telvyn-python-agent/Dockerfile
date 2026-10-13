FROM python:3.13-alpine AS package
COPY telvyn-python-agent /src
RUN pip install --no-cache-dir --target=/opt/telvyn/python /src
COPY telvyn-python-agent/injection/sitecustomize.py /opt/telvyn/python/sitecustomize.py

FROM alpine:3.20
COPY --from=package /opt/telvyn/python /opt/telvyn/python
CMD ["sh", "-c", "cp -R /opt/telvyn/python/. /target/"]
