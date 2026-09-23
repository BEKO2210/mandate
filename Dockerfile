# Mandate gateway and MCP guard.
#
#   docker build -t mandate .
#   docker run -d -p 8080:8080 -v mandate-data:/data mandate
#
# The base image is pinned by digest, so a rebuild gets the same Python, not
# whatever the tag points at that day. Update it deliberately.
ARG PYTHON_IMAGE=python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY mandate ./mandate
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[mcp]"

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# The ledger, the keys and the configuration live in /data, owned by an
# unprivileged user: a gateway that holds signing keys does not run as root.
RUN groupadd --system --gid 10001 mandate \
    && useradd --system --uid 10001 --gid 10001 --home-dir /data --shell /usr/sbin/nologin mandate \
    && mkdir -p /data && chown 10001:10001 /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels "mandate[mcp]" \
    && rm -rf /wheels
USER 10001
WORKDIR /data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]
ENTRYPOINT ["mandate"]
# The serve default binds 127.0.0.1, which a container's port mapping cannot
# reach; inside the container it has to listen on every interface.
CMD ["gateway", "serve", "--config", "/data/gateway.json", "--host", "0.0.0.0", "--port", "8080"]
