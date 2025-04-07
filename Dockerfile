# Stage 1: Build the application
FROM eclipse-temurin:21 as builder
WORKDIR /app

# Copy maven files first for better layer caching
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

# Download dependencies (this will be cached if pom.xml doesn't change)
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN ./mvnw package -DskipTests

# Stage 2: Create the runtime image
FROM eclipse-temurin:21
WORKDIR /app

RUN apt-get update && apt-get install -y \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built jar from stage 1
COPY --from=builder /app/target/phishingMailAnalyzer-2.0-SNAPSHOT.jar /app/app.jar

# Copy required model files and datasets
COPY src/main/resources/models /app/models
COPY src/main/resources/dataset /app/dataset
COPY src/main/resources/dataset/spamWords /app/dataset/spamWords

ENV PORT=8080
ENV LD_LIBRARY_PATH=/usr/lib

# Set environment variables
ENV app.dataset.path=/app/dataset/processed
ENV app.model.rf.path=/app/models/rf_model_test_new.model
ENV app.model.svm.path=/app/models/svm_model_test.model
ENV app.model.xgboost.path=/app/models/xgboost_model_test.model
ENV app.spam.words.it=/app/dataset/spamWords/it.json
ENV app.spam.words.en=/app/dataset/spamWords/en.json

# Create directory for processing feedback
RUN mkdir -p /app/dataset/processed

# Expose the port the app will run on
EXPOSE ${PORT:-8080}

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]