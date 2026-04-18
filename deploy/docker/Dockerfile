FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/iam-server ./cmd/iam-server

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/iam-server /usr/local/bin/iam-server

EXPOSE 8080
ENTRYPOINT ["iam-server"]
