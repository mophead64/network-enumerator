BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_VERSION="1.2.0"

VERSION_LDFLAGS="-X network-enumerator/internal/version.Version=${BUILD_VERSION} -X network-enumerator/internal/version.BuildDate=${BUILD_DATE}"

rm -rf ./build
mkdir -p ./build

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w ${VERSION_LDFLAGS}" -o ./build/network-enumerator-linux-amd64-${BUILD_VERSION} ./cmd/enumerator
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w ${VERSION_LDFLAGS}" -o ./build/network-enumerator-mac-arm64-${BUILD_VERSION} ./cmd/enumerator
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w ${VERSION_LDFLAGS}" -o ./build/network-enumerator-win-amd64-${BUILD_VERSION}.exe ./cmd/enumerator