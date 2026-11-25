# syntax=docker/dockerfile:1.7
# Stage 1: build the React app
FROM node:20.18.0-alpine3.20 AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Stage 2: nginx serving the SPA and reverse-proxying /api (unprivileged, ports 8080/8443)
FROM nginx:1.27.2-alpine
RUN rm -f /etc/nginx/conf.d/default.conf \
 && mkdir -p /var/cache/nginx /etc/nginx/certs \
 && chown -R nginx:nginx /var/cache/nginx /var/run /etc/nginx/conf.d \
 && sed -i 's#^pid .*#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf \
 && sed -i '/^user /d' /etc/nginx/nginx.conf
COPY deploy/nginx/infrapilot.conf deploy/nginx/proxy.inc /etc/nginx/conf.d/
COPY --from=build /src/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:8080/nginx-health || exit 1
