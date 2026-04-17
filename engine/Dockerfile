FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the embedding model at build time so the container
# starts quickly at runtime without a network fetch.
RUN python -c "\
from sentence_transformers import SentenceTransformer; \
SentenceTransformer('BAAI/bge-small-en-v1.5')"

COPY engine/ /app/engine/
COPY config/ /app/config/
COPY datacomponents/ /app/datacomponents/
COPY assets.json /app/assets.json

ENTRYPOINT ["python", "-m", "engine"]
CMD ["--config", "/app/config/detection.yml", "--mode", "stream"]
