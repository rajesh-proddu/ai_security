FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcp-sample .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-sample /mcp-sample
USER nonroot:nonroot
EXPOSE 3001
ENTRYPOINT ["/mcp-sample"]
