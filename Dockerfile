ARG PYTHON_IMAGE=python:3.12.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS frontend
WORKDIR /src
COPY upstream.lock.json ./
COPY frontend/ frontend/
COPY scripts/prepare_frontend.py scripts/prepare_frontend.py
RUN python scripts/prepare_frontend.py
COPY scripts/prepare_workspace.py scripts/prepare_workspace.py
RUN python scripts/prepare_workspace.py
COPY VERSION ./
COPY management-release.json ./management-release.json
COPY app/compatibility.py app/compatibility.py
ARG APP_VERSION
RUN python -c "import os,pathlib; from app.compatibility import WorkerCompatibility; version=pathlib.Path('VERSION').read_text().strip(); assert version == os.environ.get('APP_VERSION'), 'APP_VERSION must match VERSION'; WorkerCompatibility.load('management-release.json', version)"
COPY dashboard/ dashboard/
COPY scripts/prepare_dashboard.py scripts/prepare_dashboard.py
RUN python scripts/prepare_dashboard.py

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/vf
COPY requirements-app.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-app.lock \
    && groupadd --gid 10001 vf && useradd --uid 10001 --gid 10001 --no-create-home vf \
    && mkdir /data && chown 10001:10001 /data
COPY app/ app/
COPY --from=frontend /src/build/frontend/ build/frontend/
COPY --from=frontend /src/build/dashboard/ build/dashboard/
COPY --from=frontend /src/VERSION ./VERSION
COPY --from=frontend /src/management-release.json ./management-release.json
COPY upstream.lock.json UPSTREAM.md ./
USER 10001:10001
EXPOSE 8091
ENTRYPOINT ["python", "-m", "app.server"]
CMD ["--config", "/config/app.json"]
