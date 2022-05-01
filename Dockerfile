FROM golang:1.18 as builder

WORKDIR /

COPY . .
RUN go mod tidy
RUN go build -o app .

CMD ["./app"]


FROM alpine
RUN apk add --no-cache tzdata


WORKDIR /root
COPY --from=builder /app .
COPY --from=builder /start.sh .

EXPOSE $PORT

CMD ["sh", "start.sh"]
