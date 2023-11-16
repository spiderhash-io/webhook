ARG REGISTRY_COMMON=""
FROM ${REGISTRY_COMMON}python:3.9

WORKDIR /src

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]