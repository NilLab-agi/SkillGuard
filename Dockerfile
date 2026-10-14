# syntax=docker/dockerfile:1

# --- build stage: resolve the locked environment -------------------------
FROM python:3.12-slim AS build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Dependencies first, source second: this layer is cached until the lockfile
# changes, so editing src/ does not re-resolve anything.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra llm --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev --extra llm

# --- runtime stage: only the venv and the source ------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# A scanner reads untrusted files; it has no reason to be root.
RUN useradd --create-home --uid 10001 scanner

COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/src /app/src

USER scanner

ENTRYPOINT ["skillguard"]
CMD ["--help"]
