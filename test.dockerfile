FROM golang:1.11

WORKDIR /go/src/github.com/hellofresh/janus
COPY . .
ENTRYPOINT ["go", "test"]
