FROM openjdk:17-alpine as build-stage
WORKDIR /app
COPY . .
RUN apk add maven
RUN mvn package -Dmaven.test.skip


FROM openjdk:17-alpine as production-stage
RUN addgroup -S spring && adduser -S spring -G spring
RUN apk add --no-cache tzdata
RUN cp /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime
USER spring:spring
ARG JAR_FILE=target/*.jar
COPY --from=build-stage /app/${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar", "-Dspring.profiles.active=prod","/app.jar"]