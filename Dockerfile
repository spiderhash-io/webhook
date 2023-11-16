ARG REGISTRY_COMMON=""
FROM ${REGISTRY_COMMON}python:3.9

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY ./src /app/src

CMD ["uvicorn", "src:main:app", "--host", "0.0.0.0", "--port", "8000"]