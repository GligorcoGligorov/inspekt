# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/inspekt-api ./cmd/inspekt-worker

# Distroless static: no shell, no package manager, runs as non-root.
# One image, two programs: compose picks one with `command`.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/inspekt-api /out/inspekt-worker /
EXPOSE 8080
USER nonroot:nonroot
CMD ["/inspekt-api"]
