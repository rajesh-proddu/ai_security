FROM golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/inspector ./cmd/inspector

# The inspection service sees every prompt and tool result, so it holds no
# provider keys and gets the smallest surface we can give it (DESIGN §4).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/inspector /inspector
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/inspector"]
