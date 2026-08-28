FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/vps-audit
COPY . .
RUN pip install --no-cache-dir .
RUN mkdir -p /var/lib/vps-audit /etc/vps-audit \
    && chmod 0755 /opt/vps-audit/docker/entrypoint.sh /opt/vps-audit/docker/audit-loop.sh /opt/vps-audit/docker/healthcheck.py
USER root
ENTRYPOINT ["/opt/vps-audit/docker/entrypoint.sh"]
CMD ["/opt/vps-audit/docker/audit-loop.sh"]
