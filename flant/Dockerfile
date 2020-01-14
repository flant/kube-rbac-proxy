FROM golang:1.13.6-alpine AS build
RUN apk add --update make \
  && apk add --no-cache git
WORKDIR /go/src/github.com/flant/
RUN git clone -b flant --single-branch https://github.com/flant/kube-rbac-proxy.git \
  && cd kube-rbac-proxy \
  && make build \
  && cp /go/src/github.com/flant/kube-rbac-proxy/_output/linux/$(go env GOARCH)/kube-rbac-proxy /usr/local/bin

FROM alpine:3.10
RUN apk add -U --no-cache ca-certificates \
  && rm -rf /var/cache/apk/*
COPY --from=build /usr/local/bin/kube-rbac-proxy .
ENTRYPOINT ["./kube-rbac-proxy"]
EXPOSE 8080
