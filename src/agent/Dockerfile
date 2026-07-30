FROM python:3.11-alpine AS builder
RUN pip install --no-cache-dir cryptography httpx

FROM alpine:3.19
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY agent.py crypto.py stealth.py /opt/agent/
COPY modules/ /opt/agent/modules/
RUN adduser -D agent && chown -R agent:agent /opt/agent
USER agent
CMD ["python3", "/opt/agent/agent.py"]
