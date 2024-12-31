FROM alpine:latest AS downloader

# TOFU VERSION
ARG TOFU_VERSION=1.8.8

# TERRAGRUNT VERSION
ARG TERRAGRUNT_VERSION=0.71.1

# Install GPG and unzip
RUN apk add --no-cache gnupg cosign unzip

WORKDIR /tmp

# Download & check & unzip TOFU
ADD https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_amd64.zip tofu_${TOFU_VERSION}_linux_amd64.zip
ADD https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_SHA256SUMS tofu_${TOFU_VERSION}_SHA256SUMS
ADD https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_SHA256SUMS.sig tofu_${TOFU_VERSION}_SHA256SUMS.sig
ADD https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_SHA256SUMS.pem tofu_${TOFU_VERSION}_SHA256SUMS.pem
RUN cosign verify-blob --certificate-identity "https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/v${TOFU_VERSION%.*}" --signature "tofu_${TOFU_VERSION}_SHA256SUMS.sig" --certificate "tofu_${TOFU_VERSION}_SHA256SUMS.pem" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" tofu_${TOFU_VERSION}_SHA256SUMS
RUN grep linux_amd64.zip tofu_${TOFU_VERSION}_SHA256SUMS | sha256sum -c -
RUN unzip tofu_${TOFU_VERSION}_linux_amd64.zip

# Download TERRAGRUNT
ADD https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/terragrunt_linux_amd64 terragrunt_linux_amd64
ADD https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/SHA256SUMS terragrunt_SHA256SUMS
RUN grep linux_amd64 terragrunt_SHA256SUMS | sha256sum -c -
RUN mv terragrunt_linux_amd64 terragrunt

FROM golang:alpine

# Install bash, git and openssh and upgrade the system
RUN apk add --no-cache --upgrade bash git openssh && apk upgrade --no-cache

# Copy the binaries from the downloader stage
COPY --from=downloader /tmp/tofu /tmp/terragrunt /bin/

# Make the binaries executable
RUN chmod +x /bin/tofu
RUN chmod +x /bin/terragrunt

ENTRYPOINT ["/bin/sh", "-c"]