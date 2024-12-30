FROM golang:latest as builder
WORKDIR /DemoServer_APPLICATIONMANAGER
COPY go.mod go.sum swagger.yaml ./
RUN go mod download
COPY . .
RUN go build -o DemoServer_APPLICATIONMANAGER .


#FROM gcr.io/distroless/base-debian11
FROM cgr.dev/chainguard/glibc-dynamic
COPY --from=builder /DemoServer_APPLICATIONMANAGER/DemoServer_APPLICATIONMANAGER .
COPY --from=builder /DemoServer_APPLICATIONMANAGER/demoserver_applicationmanager_env_config.yml .

EXPOSE 5678
CMD ["/DemoServer_APPLICATIONMANAGER", "./demoserver_applicationmanager_env_config.yml"]