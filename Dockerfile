# Use the official Go image as a base image for the builder stage
FROM golang:1.24 AS builder

# Set the working directory inside the container
WORKDIR /app


# Copy the source code
COPY . .

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o tekton-dashboard-auth .

# Use a smaller image for the final stage
FROM alpine:3.21.3

# Create a non-root user and switch to it
RUN adduser -D nonrootuser
USER nonrootuser

# Set the working directory inside the container
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/tekton-dashboard-auth .

# Command to run the api
CMD ["./tekton-dashboard-auth"]
