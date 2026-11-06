FROM python:3.12.3-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY wheelhouse/ /wheelhouse/
COPY requirements.txt .

RUN pip install --no-cache-dir --no-index \
    --find-links=/wheelhouse \
    -r requirements.txt

COPY app/ ./app/
COPY docker/ ./docker/
COPY scripts/ ./scripts/

EXPOSE 17772

CMD ["python", "-m", "app.workers.pipeline_worker"]
