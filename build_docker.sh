#!/bin/bash
NAMESPACE="${1:-codebase_b87_app}"
docker build -t "$NAMESPACE" .