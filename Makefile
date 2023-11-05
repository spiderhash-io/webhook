SHELL := /bin/bash

# Install Python dependencies
.PHONY: install
install:
	pip install -r requirements.txt

# Create a new virtual environment
.PHONY: venv
venv:
	python3 -m venv venv

# Build Docker image
.PHONY: build
build:
	docker build -t webhook-app .

# Push Docker image to Docker Hub
.PHONY: push
push:
	docker push webhook-app

# Start the FastAPI application in a Docker container
.PHONY: run
run:
	docker run -d --name webhook-app -p 8000:8000 webhook-app

# Start the FastAPI application 
.PHONY: run
run-python:
	uvicorn src.main:app --reload

# Stop the FastAPI application Docker container
.PHONY: stop
stop:
	docker stop webhook-app
	docker rm webhook-app