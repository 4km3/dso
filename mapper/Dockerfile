FROM python:3.12-slim

WORKDIR /app

COPY checkov_mapper.py .
COPY severity.json .

ENTRYPOINT ["python", "checkov_mapper.py"]