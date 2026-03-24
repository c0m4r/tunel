#!/bin/bash

TOKEN=$(openssl rand -hex 32)
echo "HOST_TOKEN=$TOKEN" > .env
