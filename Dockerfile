FROM python:3.15-slim
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY --chown=65532:65532 src ./src
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
EXPOSE 8060
CMD ["/app/.venv/bin/uvicorn", "agenticos_bridge.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8060", "--no-access-log", "--no-proxy-headers", "--limit-concurrency", "64", "--timeout-keep-alive", "5"]
