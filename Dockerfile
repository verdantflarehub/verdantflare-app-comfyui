ARG PYTHON_IMAGE=python:3.12.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS frontend
WORKDIR /src
COPY upstream.lock.json ./
COPY frontend/ frontend/
COPY scripts/prepare_frontend.py scripts/prepare_frontend.py
RUN python scripts/prepare_frontend.py

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/vf
COPY requirements-app.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-app.lock \
    && groupadd --gid 10001 vf && useradd --uid 10001 --gid 10001 --no-create-home vf \
    && mkdir /data && chown 10001:10001 /data
COPY app/ app/
COPY --from=frontend /src/build/frontend/ build/frontend/
COPY upstream.lock.json UPSTREAM.md ./
USER 10001:10001
EXPOSE 8091
ENTRYPOINT ["python", "-m", "app.server"]
CMD ["--config", "/config/app.json"]
