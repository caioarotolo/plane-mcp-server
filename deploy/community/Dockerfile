FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /usr/local/bin/uv
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml uv.lock ./
COPY plane_mcp ./plane_mcp
# Reproducible dependencies; the upstream Dockerfile currently does not use its lock.
RUN uv sync --frozen --no-dev --no-editable
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 1001:1001
EXPOSE 8211
ENTRYPOINT ["python", "-m", "plane_mcp.community"]
