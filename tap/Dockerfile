FROM zeek/zeek@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5
USER root
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables tcpreplay iputils-ping && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
