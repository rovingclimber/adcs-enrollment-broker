# syntax=docker/dockerfile:1.7
ARG DOTNET_SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.400@sha256:4beef5b8919dcaa2dc924233bd069257e883cc7a061e09088a97d152d6a48510
ARG DOTNET_RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet@sha256:2d584d8147faddb0d678c5748d47953e5b8e18621ed4fb7049a91381d9d7746f
ARG SOFTHSM2_VERSION=2.6.1-2.2ubuntu3
ARG KRB5_VERSION=1.20.1-6ubuntu2.10
ARG LIBLDAP2_VERSION=2.6.10+dfsg-0ubuntu0.24.04.1
ARG SASL_GSSAPI_VERSION=2.1.28+dfsg1-5ubuntu3.1
ARG KSTART_VERSION=4.3-1

FROM ${DOTNET_SDK_IMAGE} AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       openssl=3.0.13-0ubuntu3.15 util-linux=2.39.3-9ubuntu6.6 \
       softhsm2=2.6.1-2.2ubuntu3 opensc=0.25.0~rc1-1ubuntu0.2 \
    && rm -rf /var/lib/apt/lists/*
COPY Directory.Build.props PkiProxy.slnx ./
COPY src/PkiProxy.Api/PkiProxy.Api.csproj src/PkiProxy.Api/packages.lock.json src/PkiProxy.Api/
COPY tests/PkiProxy.PublicContractTests/PkiProxy.PublicContractTests.csproj tests/PkiProxy.PublicContractTests/packages.lock.json tests/PkiProxy.PublicContractTests/
RUN dotnet restore PkiProxy.slnx --locked-mode
COPY src/PkiProxy.Api/ src/PkiProxy.Api/
COPY tests/PkiProxy.PublicContractTests/ tests/PkiProxy.PublicContractTests/
COPY lab/device-facts/ lab/device-facts/
COPY smoke/ smoke/
RUN pkcs11_root="$(mktemp -d)" \
    && export SOFTHSM2_CONF="$pkcs11_root/softhsm2.conf" \
    && mkdir "$pkcs11_root/tokens" \
    && printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$pkcs11_root/tokens" > "$SOFTHSM2_CONF" \
    && dotnet run --no-restore --project tests/PkiProxy.PublicContractTests -c Release -- --pkcs11-provider-contract \
    && rm -rf "$pkcs11_root"
RUN dotnet run --no-restore --project tests/PkiProxy.PublicContractTests -c Release
RUN dotnet publish src/PkiProxy.Api/PkiProxy.Api.csproj -c Release --no-restore /p:UseAppHost=false /p:PathMap=/src=/_/src -o /out

FROM ${DOTNET_RUNTIME_IMAGE} AS runtime
ARG SOFTHSM2_VERSION
ARG KRB5_VERSION
ARG LIBLDAP2_VERSION
ARG SASL_GSSAPI_VERSION
ARG KSTART_VERSION
WORKDIR /app
USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       "libgssapi-krb5-2=${KRB5_VERSION}" \
       "krb5-user=${KRB5_VERSION}" \
       "libldap2=${LIBLDAP2_VERSION}" \
       "libsasl2-modules-gssapi-mit=${SASL_GSSAPI_VERSION}" \
       "kstart=${KSTART_VERSION}" \
       "libsofthsm2=${SOFTHSM2_VERSION}" \
    && rm -rf /var/lib/apt/lists/*
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0
COPY --from=build --chown=$APP_UID:$APP_UID /out/ ./
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "PkiProxy.Api.dll"]
