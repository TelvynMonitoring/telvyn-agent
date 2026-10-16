FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /source
COPY telvyn-java-agent/pom.xml ./
RUN mvn -B -q dependency:go-offline
COPY telvyn-java-agent/src/ src/
RUN mvn -B -q -o -Dmaven.test.skip=true package \
 && mkdir -p /opt/telvyn/java \
 && cp target/telvyn-debugger-*.jar /opt/telvyn/java/telvyn-javaagent.jar \
 && rm -f /opt/telvyn/java/original-*

FROM alpine:3.20
COPY --from=build /opt/telvyn/java /opt/telvyn/java
CMD ["sh", "-c", "cp -R /opt/telvyn/java/. /target/"]
