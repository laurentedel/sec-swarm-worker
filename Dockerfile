FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git patch \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml worker.py ./
COPY sec_swarm ./sec_swarm

# asgiref + sqlparse are the only runtime deps of the vendored Django tree the
# PoC stage executes. The platform injects DEPLOYMENT_NAME / MISTRAL_SA_TOKEN_PATH.
RUN pip install --no-cache-dir . asgiref sqlparse

ENV PYTHONUNBUFFERED=1

CMD ["python", "worker.py"]
