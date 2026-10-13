FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS package
RUN apk add --no-cache python3
WORKDIR /src
COPY telvyn-dotnet-agent/*.csproj ./
RUN dotnet restore
COPY telvyn-dotnet-agent/*.cs ./
RUN dotnet publish --no-restore -c Release -o /out -p:CopyLocalLockFileAssemblies=true
COPY telvyn-dotnet-agent/injection/prepare-store.py /prepare-store.py
RUN python3 /prepare-store.py /out

FROM alpine:3.20
COPY --from=package /out /opt/telvyn/dotnet
CMD ["sh", "-c", "cp -R /opt/telvyn/dotnet/. /target/"]
