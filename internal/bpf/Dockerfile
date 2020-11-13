FROM debian:unstable

RUN apt-get update \
 && apt-get dist-upgrade -y \
 && apt-get install -y --no-install-recommends \
	clang \
	gcc \
	libelf-dev \
	libelf1 \
	llvm \
	make \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
