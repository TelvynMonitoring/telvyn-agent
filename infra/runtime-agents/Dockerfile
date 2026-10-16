ARG NODE_IMAGE=telvyn-node-agent:bundle
ARG PYTHON_IMAGE=telvyn-python-agent:bundle
ARG DOTNET_IMAGE=telvyn-dotnet-agent:bundle
ARG RUBY_IMAGE=telvyn-ruby-agent:bundle
ARG PHP_IMAGE=telvyn-php-agent:bundle
ARG JAVA_IMAGE=telvyn-java-agent:bundle
FROM ${NODE_IMAGE} AS node
FROM ${PYTHON_IMAGE} AS python
FROM ${DOTNET_IMAGE} AS dotnet
FROM ${RUBY_IMAGE} AS ruby
FROM ${PHP_IMAGE} AS php
FROM ${JAVA_IMAGE} AS java
FROM alpine:3.20
COPY --from=node /opt/telvyn/node /opt/telvyn/node
COPY --from=python /opt/telvyn/python /opt/telvyn/python
COPY --from=dotnet /opt/telvyn/dotnet /opt/telvyn/dotnet
COPY --from=ruby /opt/telvyn/ruby /opt/telvyn/ruby
COPY --from=php /opt/telvyn/php /opt/telvyn/php
COPY --from=java /opt/telvyn/java /opt/telvyn/java
