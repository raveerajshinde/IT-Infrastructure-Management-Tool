# syntax=docker/dockerfile:1.7
# InfraPilot API + worker image (same image, different command). Build context: repository root.
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive

# Microsoft ODBC Driver 18 + sqlcmd, ping (ICMP availability), OpenSSH client and sshpass (Ansible)
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl gnupg ca-certificates iputils-ping openssh-client sshpass unixodbc \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
    > /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update && apt-get install -y --no-install-recommends msodbcsql18 mssql-tools18 \
 && apt-get purge -y gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/infrapilot/backend
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/ /opt/infrapilot/backend/

RUN groupadd -r -g 10001 infrapilot && useradd -r -u 10001 -g infrapilot -d /var/lib/infrapilot -s /usr/sbin/nologin infrapilot \
 && mkdir -p /var/lib/infrapilot/runner /opt/infrapilot/certs \
 && chown -R infrapilot:infrapilot /var/lib/infrapilot \
 && rm -rf /opt/infrapilot/backend/tests /opt/infrapilot/backend/*.db \
 && python -m compileall -q /opt/infrapilot/backend/app

ENV IP_PLAYBOOK_DIR=/opt/infrapilot/backend/playbooks \
    IP_ANSIBLE_WORK_DIR=/var/lib/infrapilot/runner/jobs \
    IP_KNOWN_HOSTS_FILE=/var/lib/infrapilot/runner/known_hosts \
    ANSIBLE_LOCAL_TEMP=/tmp/.ansible-local ANSIBLE_HOME=/tmp/.ansible ANSIBLE_REMOTE_TEMP=/tmp/.ansible \
    HOME=/tmp PATH=/opt/mssql-tools18/bin:$PATH
USER infrapilot
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/healthz',timeout=4).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
