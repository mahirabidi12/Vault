# PkgGuard sandbox image: runs ONE package in a locked-down container and records what it does.
# Never run a suspicious package outside this image. Build context is this directory.
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      strace python3 python3-boto3 libfaketime util-linux openssl ca-certificates \
      procps curl wget netcat-openbsd git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --home-dir /home/sandbox --shell /bin/bash sandbox \
 && mkdir -p /opt/sbx /var/sbx \
 && openssl ecparam -genkey -name prime256v1 -out /opt/sbx/ca.key \
 && openssl req -x509 -new -key /opt/sbx/ca.key -days 3650 -subj "/CN=PkgGuard Sandbox CA" -out /opt/sbx/ca.pem \
 && cp /opt/sbx/ca.pem /usr/local/share/ca-certificates/pkgguard-sandbox.crt && update-ca-certificates \
 && chmod 600 /opt/sbx/ca.key

COPY runtime/ /opt/sbx/
RUN chmod -R go-w /opt/sbx && chmod 0755 /opt/sbx/*.py && chmod 600 /opt/sbx/ca.key

ENTRYPOINT ["python3", "/opt/sbx/supervisor.py"]
