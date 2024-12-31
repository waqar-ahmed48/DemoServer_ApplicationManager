FROM golang:latest as builder
WORKDIR /DemoServer_ApplicationManager
COPY go.mod go.sum swagger.yaml ./
RUN go mod download
COPY . .
RUN go build -o DemoServer_ApplicationManager .


#FROM gcr.io/distroless/base-debian11
FROM cgr.dev/chainguard/glibc-dynamic
COPY --from=builder /DemoServer_ApplicationManager/DemoServer_ApplicationManager .
COPY --from=builder /DemoServer_ApplicationManager/demoserver_applicationmanager_env_config.yml .

EXPOSE 5678
CMD ["/DemoServer_ApplicationManager", "./demoserver_applicationmanager_env_config.yml"]