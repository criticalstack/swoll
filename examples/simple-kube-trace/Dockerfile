FROM alpine:latest
WORKDIR /root/
RUN apk add --no-cache binutils
COPY simple-kube-trace ./
CMD ["./simple-kube-trace"]
