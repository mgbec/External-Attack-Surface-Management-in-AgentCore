# AgentCore Runtime container for the EASM agent.
# NOTE: `agentcore deploy` (the CLI) can generate/build this for you. This
# Dockerfile is provided for the manual / boto3 deployment path and for local
# container testing.
#
# AgentCore Runtime requires a linux/arm64 image that serves the agent on
# port 8080 at POST /invocations. The bedrock-agentcore SDK's app.run() does
# exactly that.

FROM --platform=linux/arm64 python:3.12-slim

# Avoid interactive prompts; keep the image small.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "bedrock-agentcore" "strands-agents"

# Copy the application code.
COPY easm/ ./easm/

# AgentCore Runtime invokes the container on port 8080.
EXPOSE 8080

# app.run() in easm/agent.py starts the HTTP server the runtime expects.
CMD ["python", "-m", "easm.agent"]
