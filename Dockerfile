FROM golang:1.17 AS build
WORKDIR /src
COPY ["go.mod", "go.sum", "./"]
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source https://github.com/Robbilie/oauth-client-credentials-proxy
COPY --from=build /src/oauth-client-credentials-proxy /
ENTRYPOINT ["/oauth-client-credentials-proxy"]
