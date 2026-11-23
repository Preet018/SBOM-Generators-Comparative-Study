# syntax=docker/dockerfile:1
# Variants of the Bakery backend (Spring Boot 4.1, Java 25).
# Build context: corpus/bakery-inventory-management/bakery-inventory-backend
# Planted material comes from the named context "planted" (variants/bakery-backend/planted).

# ---------- build: compile the app and record Maven's resolved dependency lists ----------
FROM maven:3-eclipse-temurin-25 AS build
WORKDIR /src
COPY pom.xml ./
COPY src ./src
# -Dmaven.test.skip=true: tests need a MySQL database. Test-scoped dependencies are still resolved by dependency:list below.
RUN mvn -B -ntp -Dmaven.test.skip=true package
RUN mkdir -p /gt /out \
 && mvn -B -ntp dependency:list -DincludeScope=runtime -DoutputFile=/gt/maven-runtime.txt \
 && mvn -B -ntp dependency:list -DoutputFile=/gt/maven-all.txt \
 && mvn -B -ntp dependency:tree -DoutputFile=/gt/maven-tree.txt \
 && cp target/bakery-inventory-management-0.0.1-SNAPSHOT.jar /out/app.jar

# ---------- planted hard cases: a manually copied old JAR and a shaded uber-JAR ----------
FROM maven:3-eclipse-temurin-25 AS planted-build
WORKDIR /planted
COPY --from=planted shaded-demo ./shaded-demo
RUN mvn -B -ntp -f shaded-demo/pom.xml package \
 && mvn -B -ntp dependency:copy -Dartifact=org.apache.logging.log4j:log4j-core:2.14.1 -DoutputDirectory=/planted/out \
 && cp shaded-demo/target/shaded-demo-1.0.0.jar /planted/out/

# ---------- S2: the built artifact on its own ----------
FROM scratch AS artifact
COPY --from=build /out/app.jar /app.jar

# ---------- build info (ground-truth inputs), exported with --output ----------
FROM scratch AS buildinfo
COPY --from=build /gt/ /

# ---------- S3 images ----------
FROM eclipse-temurin:25-jre AS s3-ubuntu
WORKDIR /app
COPY --from=build /out/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM eclipse-temurin:25-jre-alpine AS s3-alpine
WORKDIR /app
COPY --from=build /out/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM gcr.io/distroless/java25-debian13 AS s3-distroless
WORKDIR /app
COPY --from=build /out/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

# Spring Boot "extract" mode: app.jar + exploded lib/*.jar (recommended layout for containers)
FROM eclipse-temurin:25-jre AS extract
WORKDIR /x
COPY --from=build /out/app.jar ./app.jar
RUN java -Djarmode=tools -jar app.jar extract --destination /x/extracted

FROM eclipse-temurin:25-jre AS s3-layered
WORKDIR /app
COPY --from=extract /x/extracted/ /app/
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

# ---------- P: s3-ubuntu plus planted components ----------
FROM s3-ubuntu AS planted-image
COPY --from=planted-build /planted/out/log4j-core-2.14.1.jar /opt/lib/log4j-core-2.14.1.jar
COPY --from=planted-build /planted/out/shaded-demo-1.0.0.jar /opt/lib/shaded-demo-1.0.0.jar
