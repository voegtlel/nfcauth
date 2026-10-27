FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml README.md ./
COPY nfc_authenticator ./nfc_authenticator
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir .

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
