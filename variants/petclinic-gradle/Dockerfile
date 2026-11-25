# syntax=docker/dockerfile:1
# Variants of spring-petclinic built with GRADLE (Spring Boot 4.1, Java 17 toolchain).
# Build context: corpus/spring-petclinic-gradle   (upstream commit 500158f, Maven build files removed)
# Named context "p16": variants/petclinic-gradle  (init script that records Gradle's resolved artifacts)

# ---------- build: Gradle wrapper (pinned 9.5.1 by the project), JDK 17 = the project's toolchain ----------
FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY . .
COPY --from=p16 p16-resolved.init.gradle /tmp/p16-resolved.init.gradle
# -x test / -x check: tests need Docker (Testcontainers); dependency resolution is unaffected.
RUN chmod +x gradlew && ./gradlew --no-daemon -q bootJar -x test -x check
RUN mkdir -p /gt /out \
 && ./gradlew --no-daemon -q --no-configuration-cache --init-script /tmp/p16-resolved.init.gradle p16Resolved \
 && ./gradlew --no-daemon -q dependencies --configuration runtimeClasspath > /gt/gradle-runtime-tree.txt \
 && ./gradlew --version > /gt/gradle-version.txt \
 && cp "$(ls build/libs/*.jar | grep -v -- '-plain.jar')" /out/app.jar

# ---------- S2: the built artifact on its own ----------
FROM scratch AS artifact
COPY --from=build /out/app.jar /app.jar

# ---------- build info (ground-truth inputs), exported with --output ----------
FROM scratch AS buildinfo
COPY --from=build /gt/ /

# ---------- S3 images ----------
FROM eclipse-temurin:17-jre AS s3-ubuntu
WORKDIR /app
COPY --from=build /out/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM eclipse-temurin:17-jre-alpine AS s3-alpine
WORKDIR /app
COPY --from=build /out/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM gcr.io/distroless/java17-debian12 AS s3-distroless
WORKDIR /app
COPY --from=build /out/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
