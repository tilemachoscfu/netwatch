FROM python:3.12-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY netwatch ./netwatch
RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETWATCH_CONFIG=/etc/netwatch/netwatch.yaml \
    NETWATCH_DATABASE_PATH=/data/netwatch.db
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping nmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 netwatch \
    && useradd --uid 10001 --gid 10001 --no-create-home netwatch \
    && mkdir -p /data /etc/netwatch \
    && chown 10001:10001 /data \
    && chmod 700 /data
COPY --from=builder /wheels /wheels
COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt /wheels/*.whl \
    && rm -rf /wheels /tmp/requirements.txt
COPY netwatch.example.yaml /etc/netwatch/netwatch.yaml
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
HEALTHCHECK --interval=60s --timeout=15s --start-period=90s --retries=3 \
    CMD ["netwatch", "healthcheck"]
ENTRYPOINT ["netwatch"]
CMD ["monitor"]
