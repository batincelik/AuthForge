FROM python:3.13-slim
WORKDIR /srv/authforge
COPY pyproject.toml alembic.ini ./
COPY apps/api ./apps/api
COPY apps/worker ./apps/worker
COPY apps/oauth-fixture ./apps/oauth-fixture
COPY scripts ./scripts
RUN --mount=type=cache,target=/root/.cache/pip pip install .
ENV PYTHONPATH=/srv/authforge/apps/api
CMD ["sh", "apps/api/start.sh"]
