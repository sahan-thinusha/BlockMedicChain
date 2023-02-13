FROM golang:1.18-alpine

RUN apk add --no-cache git

WORKDIR /

COPY . .
RUN go mod tidy
# Build the Go app
RUN go build -o app .



EXPOSE $PORT

# Run the binary program produced by `go install`
CMD ["./app"]
