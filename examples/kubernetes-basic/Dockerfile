FROM alpine:latest
WORKDIR /root/
RUN apk add --no-cache binutils
COPY kube-trace ./
CMD ["./kube-trace"]
