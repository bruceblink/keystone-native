FROM quay.io/quarkus/ubi-quarkus-mandrel-builder-image:latest AS build
USER quarkus
WORKDIR /project
COPY --chown=quarkus:quarkus build.gradle settings.gradle gradle.properties gradlew ./
COPY --chown=quarkus:quarkus gradle gradle
COPY --chown=quarkus:quarkus src src
RUN ./gradlew --no-daemon nativeBuild -Dquarkus.native.container-build=true -x test

FROM quay.io/quarkus/quarkus-micro-image:2.0
WORKDIR /work/
COPY --from=build /project/build/keystone-native-*-runner /work/application
RUN chmod 775 /work /work/application
EXPOSE 8080
USER 1001
ENTRYPOINT ["/work/application", "-Dquarkus.http.host=0.0.0.0"]
