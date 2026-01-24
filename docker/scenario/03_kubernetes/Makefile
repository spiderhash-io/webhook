# Makefile for Kubernetes Local Testing Scenario
.PHONY: setup deploy test clean all help status logs

# Default test type
TEST_TYPE ?= basic

help:
	@echo "Kubernetes Local Testing Scenario"
	@echo ""
	@echo "Usage:"
	@echo "  make setup          - Create kind cluster and build/load image"
	@echo "  make deploy         - Deploy manifests to cluster"
	@echo "  make test           - Run basic tests"
	@echo "  make test-scaling   - Run scaling tests (includes HPA)"
	@echo "  make test-ingress   - Run ingress tests"
	@echo "  make test-all       - Run all tests"
	@echo "  make clean          - Delete kind cluster"
	@echo "  make all            - Run complete test cycle (setup + deploy + test)"
	@echo "  make status         - Show cluster status"
	@echo "  make logs           - Show pod logs"
	@echo "  make port-forward   - Start port forwarding"
	@echo ""

setup:
	@./scripts/setup.sh

deploy:
	@./scripts/deploy.sh

deploy-full:
	@./scripts/deploy.sh --all

test:
	@./scripts/test.sh basic

test-scaling:
	@./scripts/deploy.sh --with-hpa
	@./scripts/test.sh scaling

test-ingress:
	@./scripts/deploy.sh --with-ingress
	@./scripts/test.sh ingress

test-all:
	@./scripts/deploy.sh --all
	@./scripts/test.sh all

clean:
	@./scripts/cleanup.sh --force

clean-logs:
	@./scripts/cleanup.sh --force --logs

all: clean setup deploy test

status:
	@echo "=== Cluster Info ==="
	@kubectl cluster-info --context kind-webhook-test 2>/dev/null || echo "Cluster not running"
	@echo ""
	@echo "=== Pods ==="
	@kubectl get pods -n webhook-system 2>/dev/null || echo "No pods found"
	@echo ""
	@echo "=== Services ==="
	@kubectl get svc -n webhook-system 2>/dev/null || echo "No services found"
	@echo ""
	@echo "=== HPA ==="
	@kubectl get hpa -n webhook-system 2>/dev/null || echo "No HPA configured"

logs:
	@kubectl logs -n webhook-system -l app.kubernetes.io/name=core-webhook-module -f --tail=50

port-forward:
	@echo "Starting port-forward on localhost:8000..."
	@kubectl port-forward -n webhook-system svc/webhook-service 8000:80
