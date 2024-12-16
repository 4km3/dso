# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum files (if they exist)
COPY index.html ./

COPY style.css ./

# Download dependencies (if go.mod exists)
# RUN if [ -f go.mod ]; then go mod download; fi

# Copy the source code
COPY embedded-static-server.go .

RUN go mod init 4km3/dso
RUN go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o myapp .

# Final stage
FROM scratch

# Copy SSL certificates from the builder stage (if your app needs HTTPS)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from builder
COPY --from=builder /app/myapp /

# Expose any necessary ports (replace 8080 with your app's port)
EXPOSE 8080

# Set the binary as the entrypoint
ENTRYPOINT ["/myapp"]