# DProxyClient.net
A .NET and C# implementation of a DProxy compatible servers.

## Run
```shell
dotnet run --project=DProxyClient
```

## Build a release version
```shell
dotnet restore
dotnet build --no-restore
dotnet publish --configuration Release -p:ServerAddress="localhost" -p:Version=$(git rev-parse --short HEAD) -p:PublishSingleFile=true
```
