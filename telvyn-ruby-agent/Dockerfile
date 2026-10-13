FROM ruby:3.3-alpine AS package
RUN apk add --no-cache build-base
WORKDIR /src
COPY telvyn-ruby-agent ./
RUN gem build telvyn-ruby-agent.gemspec && gem install --no-document --install-dir /opt/telvyn/ruby telvyn-ruby-agent-0.1.0.gem
RUN cp injection/inject.rb /opt/telvyn/ruby/inject.rb

FROM alpine:3.20
COPY --from=package /opt/telvyn/ruby /opt/telvyn/ruby
CMD ["sh", "-c", "cp -R /opt/telvyn/ruby/. /target/"]
