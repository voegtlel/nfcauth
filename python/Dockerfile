FROM python:3.12-slim AS builder

ARG UV_VERSION=0.13.5
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV VIRTUAL_ENV=/opt/venv
WORKDIR /build
COPY pyproject.toml uv.lock README.md ./
COPY nfc_authenticator ./nfc_authenticator
RUN python -m pip install --no-cache-dir "uv==${UV_VERSION}" \
    && python -m venv /opt/venv \
    && uv sync --frozen --no-dev --no-editable --active

FROM python:3.12-slim
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --system nfcauth && useradd --system --gid nfcauth --home /nonexistent nfcauth
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER nfcauth
EXPOSE 8080
ENTRYPOINT ["nfc-auth-bridge"]
