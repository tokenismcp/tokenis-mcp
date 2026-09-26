# syntax=docker/dockerfile:1.7
# Tokenis MCP server.
#
#   docker build -t tokenis-mcp .
#   docker run -i --rm tokenis-mcp                        # stdio, fictional demo data
#   docker run --rm -p 8000:8000 -v "$PWD/deploy:/config" \
#     -e TOKENIS_TOKENIZER_KEY -e TOKENIS_AUDIT_KEY \
#     tokenis-mcp serve --config /config/tokenis.toml --transport http --host 0.0.0.0
#
# The image holds no data and no secrets: mount the config (and keystore or
# ledger), and pass credentials as environment variables. A full stack with
# PostgreSQL, replicas and monitoring is in deploy/compose; Kubernetes in
# deploy/helm.

FROM python:3.12-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates build-essential \
 && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip install --no-cache-dir "maturin>=1.7,<2"
WORKDIR /src
COPY Cargo.toml Cargo.lock pyproject.toml README.md LICENSE THIRD-PARTY-NOTICES.md ./
COPY crates ./crates
COPY tokenis ./tokenis
RUN maturin build --release --locked --out /dist

FROM python:3.12-slim-bookworm
# Drivers baked into the image: shared state and database sources
# (PostgreSQL, MySQL, Oracle, SQL Server) and every key-management service.
# Add snowflake/bigquery, or trim, with --build-arg TOKENIS_EXTRAS=...
ARG TOKENIS_EXTRAS="postgres,mysql,oracle,mssql,aws,gcp,azure"
LABEL org.opencontainers.image.title="Tokenis MCP server" \
      org.opencontainers.image.source="https://github.com/tokenismcp/tokenis-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.modelcontextprotocol.server.name="io.github.tokenismcp/tokenis-mcp"
COPY --from=build /dist /tmp/dist
RUN wheel="$(ls /tmp/dist/*.whl)" \
 && pip install --no-cache-dir "${wheel}${TOKENIS_EXTRAS:+[$TOKENIS_EXTRAS]}" && rm -rf /tmp/dist \
 && useradd --create-home --uid 10001 tokenis \
 && mkdir -p /config && chown tokenis:tokenis /config
USER tokenis
WORKDIR /config
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
ENTRYPOINT ["tokenis-mcp"]
CMD ["serve", "--demo"]
