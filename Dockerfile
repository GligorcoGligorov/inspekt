# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/inspekt-api ./cmd/inspekt-api

# Distroless static: no shell, no package manager, runs as non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/inspekt-api /inspekt-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/inspekt-api"]
