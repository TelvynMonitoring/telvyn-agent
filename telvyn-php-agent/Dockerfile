FROM composer:2 AS composer
FROM php:8.3-cli-alpine AS package
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
WORKDIR /opt/telvyn/php
COPY telvyn-php-agent ./
RUN composer install --no-dev --no-interaction --prefer-dist --no-scripts

FROM alpine:3.20
COPY --from=package /opt/telvyn/php /opt/telvyn/php
CMD ["sh", "-c", "cp -R /opt/telvyn/php/. /target/"]
