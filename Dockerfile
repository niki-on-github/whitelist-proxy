FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /whitelist-proxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /whitelist-proxy /whitelist-proxy
EXPOSE 8080 8081
ENTRYPOINT ["/whitelist-proxy"]