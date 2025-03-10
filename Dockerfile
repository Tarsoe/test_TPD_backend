# # Use an official OpenJDK runtime as a parent image
# FROM openjdk:17-jdk-alpine

# # Set the working directory
# WORKDIR /app

# # Copy the application's jar to the container
# COPY target/matching-0.0.1-SNAPSHOT.jar /app/matching.jar

# # Expose port 8080 for the application
# EXPOSE 8080

# # Run the Spring Boot application
# ENTRYPOINT ["java", "-jar", "/app/matching.jar"]

# End
FROM maven:3.8.5-openjdk-17 AS build
COPY . .
RUN mvn clean package -DskipTests

FROM openjdk:17.0.1-jdk-slim
COPY --from=build /target/matching-0.0.1-SNAPSHOT.jar matching.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","matching.jar"]