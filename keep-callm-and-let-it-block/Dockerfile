FROM python:3.12.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.12.0 /uv /uvx /bin/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable && useradd --uid 10001 --create-home workshop && mkdir /data && chown workshop /data
USER workshop
EXPOSE 8000 8081
CMD ["python", "-m", "romhack"]
