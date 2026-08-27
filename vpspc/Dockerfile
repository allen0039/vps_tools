FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/vps-audit
COPY . .
RUN pip install --no-cache-dir .
RUN mkdir -p /var/lib/vps-audit /etc/vps-audit
USER root
ENTRYPOINT ["/opt/vps-audit/docker/audit-loop.sh"]
