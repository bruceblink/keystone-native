# syntax=docker/dockerfile:1.7
FROM quay.io/quarkus/ubi-quarkus-mandrel-builder-image@sha256:c5d1cbf82de4c9eb95135d85280f9d3b43cbdd6313913264fd7fc6c0abdedbd7 AS build
USER quarkus
WORKDIR /project
ARG GRADLE_PROXY_HOST
ARG GRADLE_PROXY_PORT
COPY --chown=quarkus:quarkus build.gradle settings.gradle gradle.properties gradlew ./
COPY --chown=quarkus:quarkus gradle gradle
COPY --chown=quarkus:quarkus src src
RUN --mount=type=secret,id=proxy-ca,target=/tmp/proxy-ca.crt,uid=1001,gid=1001,mode=0444 \
    proxy_opts=""; \
    if [ -n "${GRADLE_PROXY_HOST}" ] && [ -n "${GRADLE_PROXY_PORT}" ]; then \
      proxy_opts="-Dhttps.proxyHost=${GRADLE_PROXY_HOST} -Dhttps.proxyPort=${GRADLE_PROXY_PORT} -Dhttp.proxyHost=${GRADLE_PROXY_HOST} -Dhttp.proxyPort=${GRADLE_PROXY_PORT}"; \
    fi; \
    if [ -s /tmp/proxy-ca.crt ]; then \
      keytool -importcert -noprompt -alias build-proxy -file /tmp/proxy-ca.crt -keystore /tmp/gradle-truststore.p12 -storetype PKCS12 -storepass changeit; \
      proxy_opts="${proxy_opts} -Djavax.net.ssl.trustStore=/tmp/gradle-truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit"; \
    fi; \
    export JAVA_TOOL_OPTIONS="${proxy_opts}"; \
    ./gradlew --no-daemon nativeBuild -x test

FROM quay.io/quarkus/quarkus-micro-image@sha256:5f3b9c2c6868e14e899f682ebd42e2d0cd519e457dfe0698f58a81d6a26593c6
WORKDIR /work/
COPY --from=build /project/build/keystone-native-*-runner /work/application
RUN chmod 775 /work /work/application
EXPOSE 8080
USER 1001
ENTRYPOINT ["/work/application", "-Dquarkus.http.host=0.0.0.0"]
