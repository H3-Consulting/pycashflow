# syntax=docker/dockerfile:1

FROM python:3.14.7-alpine

ARG DOCKER_TAG
ENV DOCKER_TAG=$DOCKER_TAG
ENV APP_VERSION=$DOCKER_TAG

WORKDIR /app

COPY requirements.txt requirements.txt
COPY constraints.txt constraints.txt
# RUN pip3 install -r requirements.txt
# install everything except greenlet
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

RUN apk --no-cache add su-exec tzdata

# Create a dedicated non-root runtime user and group
RUN addgroup -S appgroup && adduser -S -G appgroup appuser

COPY . .

COPY entry.sh /entry.sh
RUN chmod +x /entry.sh

# Create SQLite data directory, log files, then hand ownership to appuser.
# Crontab spool file is set up AFTER the chown-R so it stays root:root (mode
# 600) — busybox crond refuses to run a spool file that isn't owned by root.
RUN mkdir -p /app/app/data && \
    touch /app/getemail.log /app/crond.log && \
    chown -R appuser:appgroup /app /entry.sh && \
    mkdir -p /app/crontabs && \
    cp /app/crontab.txt /app/crontabs/appuser && \
    chown root:root /app/crontabs /app/crontabs/appuser && \
    chmod 600 /app/crontabs/appuser

ENV PYTHONPATH=/app
ENV DATABASE_URL=sqlite:////app/app/data/db.sqlite

HEALTHCHECK CMD python -c "import sys, urllib.request; sys.exit(0) if urllib.request.urlopen('http://localhost:5000/healthz', timeout=5).getcode() < 400 else sys.exit(1)"

EXPOSE 5000

CMD ["/entry.sh"]
