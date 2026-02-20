# build
FROM golang:1.22-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/runner ./main.go

# runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -u 10001 runner
USER runner
WORKDIR /app
COPY --from=build /out/runner /app/runner
EXPOSE 8080
ENTRYPOINT ["/app/runner"]
