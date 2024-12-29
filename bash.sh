#!/bin/bash

# Kolory do lepszej czytelności
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Katalogi instalacji
INSTALL_DIR="/opt/ghost"
BACKUP_DIR="/opt/ghost/backup"
LOG_DIR="/var/log/ghost"
MONITORING_DIR="/opt/monitoring"
SCRIPT_LOG="/var/log/ghost-install.log"
CREDENTIALS_FILE="/root/.ghost_credentials/credentials.txt"

# Funkcja generowania losowego portu
generate_random_port() {
    local min_port=10000
    local max_port=65535
    local port
    local used_ports=()

    # Zbierz wszystkie używane porty
    while IFS= read -r line; do
        used_ports+=($line)
    done < <(netstat -tuln | grep "LISTEN" | awk '{print $4}' | awk -F: '{print $NF}')
    
    while true; do
        # Generuj losowy port
        port=$(shuf -i $min_port-$max_port -n 1)
        
        # Sprawdź czy port nie jest już używany
        if [[ ! " ${used_ports[@]} " =~ " ${port} " ]]; then
            # Dodatkowe sprawdzenie netstat
            if ! netstat -tuln | grep -q ":$port "; then
                echo $port
                return 0
            fi
        fi
    done
}

# Generowanie losowych portów
GRAFANA_PORT=$(generate_random_port)
PROMETHEUS_PORT=$(generate_random_port)
LOKI_PORT=$(generate_random_port)

# Funkcja rotacji logów
setup_log_rotation() {
    cat > /etc/logrotate.d/ghost <<EOF
$SCRIPT_LOG {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        systemctl reload syslog >/dev/null 2>&1 || true
    endscript
}
EOF
}

# Funkcja logowania
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $SCRIPT_LOG
}

error() {
    echo -e "${RED}[ERROR][$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $SCRIPT_LOG
    cleanup_and_exit
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING][$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $SCRIPT_LOG
}

# Funkcja sprzątająca
cleanup_and_exit() {
    log "Czyszczenie tymczasowych plików..."
    # Dodaj tutaj czyszczenie plików tymczasowych
    rm -f /tmp/ghost_install_*
}

# Walidacja hasła
validate_password() {
    local pass="$1"
    local min_length=16
    local max_length=128
    
    # Sprawdź długość
    if [[ ${#pass} -lt $min_length ]] || [[ ${#pass} -gt $max_length ]]; then
        return 1
    fi
    
    # Sprawdź złożoność
    if [[ ! $pass =~ [A-Z] ]] || \
       [[ ! $pass =~ [a-z] ]] || \
       [[ ! $pass =~ [0-9] ]] || \
       [[ ! $pass =~ [^[:alnum:]] ]]; then
        return 1
    fi
    
    # Sprawdź niebezpieczne znaki
    if [[ $pass =~ [\'\"\\] ]]; then
        return 1
    fi
    
    # Sprawdź białe znaki
    if [[ $pass =~ [[:space:]] ]]; then
        return 1
    fi
    
    # Sprawdź powtarzające się znaki
    if [[ $pass =~ (.)\1{2,} ]]; then
        return 1
    fi
    
    # Sprawdź sekwencje
    if [[ $pass =~ (abc|123|qwe|ABC) ]]; then
        return 1
    fi
    
    return 0
}

# Generowanie bezpiecznego hasła
generate_secure_password() {
    local length=$1
    local pass
    local charset='A-Za-z0-9!@#$%^&*()_+=-'
    
    # Sprawdź limity długości
    if [ $length -lt 16 ]; then
        length=16
    elif [ $length -gt 128 ]; then
        length=128
    fi
    
    while true; do
        # Generuj hasło z różnych źródeł entropii
        pass=$(cat /dev/urandom | tr -dc "$charset" | fold -w $length | head -n 1)
        
        # Sprawdź czy hasło spełnia wymagania
        if validate_password "$pass"; then
            echo "$pass"
            break
        fi
    done
}

# Generowanie i szyfrowanie danych dostępowych
generate_secure_credentials() {
    log "Generowanie bezpiecznych danych dostępowych..."
    
    # Generowanie haseł
    MYSQL_ROOT_PASSWORD=$(generate_secure_password 64)
    MYSQL_PASSWORD=$(generate_secure_password 48)
    REDIS_PASSWORD=$(generate_secure_password 48)
    GRAFANA_ADMIN_PASSWORD=$(generate_secure_password 32)
    PROMETHEUS_PASSWORD=$(generate_secure_password 32)
    LOKI_PASSWORD=$(generate_secure_password 32)

    # Generowanie nazw użytkowników i baz danych
    DB_NAME="ghost_$(date +%Y%m%d)_$(openssl rand -hex 4)"
    DB_USER="ghost_$(openssl rand -hex 6)"
    
    # Zapisanie danych w pliku credentials
    mkdir -p $(dirname $CREDENTIALS_FILE)
    cat > $CREDENTIALS_FILE <<EOF
# Ghost Installation Credentials
# Generated: $(date)
# WAŻNE: Ten plik jest zaszyfrowany. Klucz deszyfrujący znajduje się w ${CREDENTIALS_FILE}.key

=== PORTY USŁUG ===
Grafana Port: $GRAFANA_PORT
Prometheus Port: $PROMETHEUS_PORT
Loki Port: $LOKI_PORT

=== DATABASE CREDENTIALS ===
Database Name: $DB_NAME
Database User: $DB_USER
Database Password: $MYSQL_PASSWORD
Database Root Password: $MYSQL_ROOT_PASSWORD

=== REDIS CREDENTIALS ===
Redis Password: $REDIS_PASSWORD

=== MONITORING CREDENTIALS ===
Grafana Admin Password: $GRAFANA_ADMIN_PASSWORD
Prometheus Password: $PROMETHEUS_PASSWORD
Loki Password: $LOKI_PASSWORD

=== ACCESS URLS ===
Ghost Admin: https://$DOMAIN/ghost
Grafana: https://$DOMAIN:$GRAFANA_PORT
Prometheus: https://$DOMAIN:$PROMETHEUS_PORT
EOF

    # Szyfrowanie pliku z danymi
    encrypt_credentials
}

# Funkcja szyfrowania credentials
encrypt_credentials() {
    local key=$(openssl rand -hex 32)
    local iv=$(openssl rand -hex 16)
    
    # Szyfrowanie z użyciem AES-256-GCM
    openssl enc -aes-256-gcm -salt \
        -in "$CREDENTIALS_FILE" \
        -out "${CREDENTIALS_FILE}.enc" \
        -K "$key" \
        -iv "$iv" \
        -iter 100000
        
    # Zapisanie klucza i IV w bezpiecznym miejscu
    echo "Encryption Key: $key" > "${CREDENTIALS_FILE}.key"
    echo "IV: $iv" >> "${CREDENTIALS_FILE}.key"
    chmod 600 "${CREDENTIALS_FILE}.key"
    
    # Usunięcie oryginalnego pliku
    shred -u "$CREDENTIALS_FILE"
    mv "${CREDENTIALS_FILE}.enc" "$CREDENTIALS_FILE"
}

# Sprawdzanie wymagań systemowych
check_system_requirements() {
    log "Sprawdzanie wymagań systemowych..."
    
    # Sprawdź minimalne wymagania RAM
    total_memory=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_memory -lt 2048 ]; then
        error "Wymagane minimum 2GB RAM"
    fi
    
    # Sprawdź dostępne miejsce na dysku
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        error "Wymagane minimum 10GB wolnego miejsca na dysku"
    fi
    
    # Sprawdź wersję systemu
    if [ ! -f /etc/os-release ]; then
        error "Nie można określić wersji systemu"
    fi
    . /etc/os-release
    if [[ ! $VERSION_ID =~ ^(20.04|22.04)$ ]]; then
        error "Wymagana Ubuntu 20.04 LTS lub 22.04 LTS"
    fi
    
    # Sprawdź wymagane pakiety
    required_packages=(docker.io docker-compose curl wget openssl)
    missing_packages=()
    
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            missing_packages+=($package)
        fi
    done
    
    if [ ${#missing_packages[@]} -ne 0 ]; then
        log "Instalacja brakujących pakietów: ${missing_packages[*]}"
        apt-get update
        apt-get install -y "${missing_packages[@]}"
    fi
}

# Sprawdzanie zajętych portów
check_ports() {
    local ports=($GRAFANA_PORT $PROMETHEUS_PORT $LOKI_PORT)
    for port in "${ports[@]}"; do
        if netstat -tuln | grep -q ":$port "; then
            error "Port $port jest już zajęty"
        fi
    done
}

# Konfiguracja Grafany z zabezpieczeniami
setup_grafana() {
    log "Konfiguracja Grafany..."
    
    cat > $MONITORING_DIR/grafana/grafana.ini <<EOF
[server]
http_port = $GRAFANA_PORT
domain = $DOMAIN
root_url = https://$DOMAIN:$GRAFANA_PORT
cert_file = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
cert_key = /etc/letsencrypt/live/$DOMAIN/privkey.pem
protocol = https

[security]
admin_user = admin
admin_password = $GRAFANA_ADMIN_PASSWORD
secret_key = $(openssl rand -hex 32)
disable_gravatar = true
cookie_secure = true
cookie_samesite = strict
allow_embedding = false
strict_transport_security = true
strict_transport_security_max_age_seconds = 31536000
strict_transport_security_preload = true
strict_transport_security_subdomains = true
x_content_type_options = true
x_xss_protection = true

[auth]
disable_login_form = false
login_maximum_inactive_lifetime_days = 7
login_maximum_lifetime_days = 30
disable_brute_force_login_protection = false
max_login_attempts = 5
minimum_password_length = 16
password_require_uppercase = true
password_require_lowercase = true
password_require_number = true
password_require_special = true

[analytics]
reporting_enabled = false
check_for_updates = false

[snapshots]
external_enabled = false

[users]
allow_sign_up = false
default_theme = dark
auto_assign_org_role = Viewer

[auth.anonymous]
enabled = false

[session]
provider = redis
provider_config = addr=redis:6379,password=${REDIS_PASSWORD},db=0,pool_size=100,idle_timeout=30s

[log]
mode = console file
level = info
filters = rotating:maxfiles=10,maxsize=10MB
EOF

    # Dodanie dashboardów monitoringu
    mkdir -p $MONITORING_DIR/grafana/provisioning/dashboards
    cat > $MONITORING_DIR/grafana/provisioning/dashboards/ghost.json <<EOF
{
  "annotations": {
    "list": []
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "links": [],
  "liveNow": false,
  "panels": [
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "smooth",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "none"
        }
      },
      "title": "Ghost Performance Metrics",
      "type": "timeseries"
    }
  ],
  "schemaVersion": 38,
  "style": "dark",
  "tags": ["ghost"],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "title": "Ghost Dashboard",
  "uid": "ghost_metrics",
  "version": 1
}
EOF
}

# Konfiguracja Prometheusa z zabezpieczeniami
setup_prometheus() {
    log "Konfiguracja Prometheusa..."
    
    # Generowanie hasła bcrypt dla basic auth
    PROMETHEUS_HTPASSWD=$(htpasswd -nbB admin $PROMETHEUS_PASSWORD)
    
    cat > $MONITORING_DIR/prometheus/prometheus.yml <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'ghost-monitor'

# Basic auth configuration
basic_auth_users:
  admin: ${PROMETHEUS_HTPASSWD#admin:}

scrape_configs:
  - job_name: 'ghost'
    metrics_path: '/metrics'
    scheme: https
    basic_auth:
      username: admin
      password: ${PROMETHEUS_PASSWORD}
    tls_config:
      cert_file: /etc/letsencrypt/live/$DOMAIN/cert.pem
      key_file: /etc/letsencrypt/live/$DOMAIN/privkey.pem
      insecure_skip_verify: false
    static_configs:
      - targets: ['ghost:2368']
    
  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
    
  - job_name: 'mysql'
    static_configs:
      - targets: ['mysqld-exporter:9104']
    
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
    
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']

  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
        - https://${DOMAIN}
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

# Alerting rules
rule_files:
  - /etc/prometheus/rules/*.yml

alerting:
  alertmanagers:
  - static_configs:
    - targets:
      - 'alertmanager:9093'
EOF

    # Konfiguracja reguł alertów
    mkdir -p $MONITORING_DIR/prometheus/rules
    cat > $MONITORING_DIR/prometheus/rules/ghost_alerts.yml <<EOF
groups:
- name: ghost_alerts
  rules:
  - alert: HighMemoryUsage
    expr: process_resident_memory_bytes{job="ghost"} > 1.5e+9
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High memory usage in Ghost (instance {{ \$labels.instance }})
      description: Ghost memory usage is above 1.5GB for 5 minutes

  - alert: HighCPUUsage
    expr: rate(process_cpu_seconds_total{job="ghost"}[5m]) * 100 > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High CPU usage in Ghost (instance {{ \$labels.instance }})
      description: Ghost CPU usage is above 80% for 5 minutes

  - alert: SSLCertificateExpiringSoon
    expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 30
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "SSL Certificate expiring soon for {{ \$labels.instance }}"
      description: "SSL certificate will expire in less than 30 days"

  - alert: HighDatabaseConnections
    expr: mysql_global_status_threads_connected > 100
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High number of database connections
      description: More than 100 active database connections

  - alert: SlowQueries
    expr: rate(mysql_global_status_slow_queries[5m]) > 0
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: Slow queries detected
      description: Database is experiencing slow queries

  - alert: HighRedisMemory
    expr: redis_memory_used_bytes / redis_memory_max_bytes * 100 > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High Redis memory usage
      description: Redis memory usage is above 80%

  - alert: GhostDown
    expr: up{job="ghost"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: Ghost is down
      description: Ghost instance has been down for more than 2 minutes

  - alert: DatabaseDown
    expr: up{job="mysql"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: Database is down
      description: MySQL database has been down for more than 1 minute

  - alert: RedisDown
    expr: up{job="redis"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: Redis is down
      description: Redis instance has been down for more than 1 minute

  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) * 100 > 5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High error rate
      description: More than 5% of requests are resulting in errors
EOF
}

# Konfiguracja Loki z zabezpieczeniami
setup_loki() {
    log "Konfiguracja Loki..."
    
    cat > $MONITORING_DIR/loki/loki.yml <<EOF
auth_enabled: true

server:
  http_listen_port: ${LOKI_PORT}
  http_server_read_timeout: 120s
  http_server_write_timeout: 120s
  http_server_idle_timeout: 120s

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s
  wal:
    enabled: true
    dir: /tmp/loki/wal

schema_config:
  configs:
    - from: 2023-01-01
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /tmp/loki/index
    cache_location: /tmp/loki/cache
    shared_store: filesystem
  filesystem:
    directory: /tmp/loki/chunks

compactor:
  working_directory: /tmp/loki/compactor
  shared_store: filesystem
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 150

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  max_cache_freshness_per_query: 10m
  split_queries_by_interval: 15m
  ingestion_rate_mb: 4
  ingestion_burst_size_mb: 6
  max_query_series: 500
  max_query_parallelism: 32

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: true
  retention_period: 168h

frontend:
  max_outstanding_per_tenant: 2048
  compress_responses: true

analytics:
  reporting_enabled: false

security:
  # Basic authentication configuration
  auth:
    type: basic
    basic:
      username: admin
      password: ${LOKI_PASSWORD}
EOF
}

# Konfiguracja Docker Compose
setup_docker_compose() {
    log "Konfiguracja Docker Compose..."
    
    cat > $INSTALL_DIR/docker-compose.yml <<EOF
version: '3.8'

x-logging: &default-logging
  options:
    max-size: "10m"
    max-file: "3"

services:
  ghost:
    image: ghost:latest@${GHOST_IMAGE_HASH}
    restart: unless-stopped
    environment:
      url: https://${DOMAIN}
      database__client: mysql
      database__connection__host: db
      database__connection__user: ${DB_USER}
      database__connection__password: ${MYSQL_PASSWORD}
      database__connection__database: ${DB_NAME}
      NODE_ENV: production
      mail__transport: SMTP
      mail__options__host: ${SMTP_HOST:-smtp.example.com}
      mail__options__port: ${SMTP_PORT:-587}
      mail__options__auth__user: ${SMTP_USER:-user}
      mail__options__auth__pass: ${SMTP_PASS:-pass}
    volumes:
      - ghost-content:/var/lib/ghost/content
    depends_on:
      - db
      - redis
    networks:
      - ghost-internal
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:2368/ghost/api/v3/admin/site/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    security_opt:
      - no-new-privileges:true
    logging: *default-logging
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ghost.rule=Host(\`${DOMAIN}\`)"
      - "traefik.http.routers.ghost.tls=true"
      - "traefik.http.routers.ghost.middlewares=secure-headers"
      - "traefik.http.middlewares.secure-headers.headers.sslRedirect=true"
      - "traefik.http.middlewares.secure-headers.headers.stsSeconds=31536000"
      - "traefik.http.middlewares.secure-headers.headers.stsIncludeSubdomains=true"
      - "traefik.http.middlewares.secure-headers.headers.stsPreload=true"

  db:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
    volumes:
      - mysql-data:/var/lib/mysql
      - ./mysql.cnf:/etc/mysql/conf.d/custom.cnf:ro
    networks:
      - ghost-internal
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u$$MYSQL_USER", "-p$$MYSQL_PASSWORD"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging
    command: [
      '--character-set-server=utf8mb4',
      '--collation-server=utf8mb4_unicode_ci',
      '--default-authentication-plugin=mysql_native_password',
      '--max-connections=1000',
      '--innodb-buffer-pool-size=1G'
    ]

  redis:
    image: redis:alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    networks:
      - ghost-internal
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "$$REDIS_PASSWORD", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging

  grafana:
    image: grafana/grafana:latest
    restart: unless-stopped
    volumes:
      - ./grafana:/etc/grafana:ro
      - grafana-data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      - GF_SERVER_ROOT_URL=https://${DOMAIN}:${GRAFANA_PORT}
      - GF_SECURITY_ALLOW_EMBEDDING=false
      - GF_SECURITY_COOKIE_SECURE=true
      - GF_SECURITY_COOKIE_SAMESITE=strict
    ports:
      - "127.0.0.1:${GRAFANA_PORT}:3000"
    networks:
      - monitoring
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging

  prometheus:
    image: prom/prometheus:latest
    restart: unless-stopped
    volumes:
      - ./prometheus:/etc/prometheus:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=15d'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
      - '--web.external-url=https://${DOMAIN}:${PROMETHEUS_PORT}'
      - '--web.enable-admin-api=false'
    ports:
      - "127.0.0.1:${PROMETHEUS_PORT}:9090"
    networks:
      - monitoring
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:9090/-/healthy || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging

loki:
    image: grafana/loki:latest
    restart: unless-stopped
    volumes:
      - ./loki:/etc/loki:ro
      - loki-data:/loki
    command: -config.file=/etc/loki/loki.yml
    ports:
      - "127.0.0.1:${LOKI_PORT}:3100"
    networks:
      - monitoring
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:3100/ready || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging

  node-exporter:
    image: prom/node-exporter:latest
    restart: unless-stopped
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.ignored-mount-points=^/(sys|proc|dev|host|etc)($$|/)'
      - '--no-collector.arp'
      - '--no-collector.netclass'
      - '--no-collector.netstat'
      - '--no-collector.wireless'
      - '--collector.netdev.device-exclude=^(veth.*|br.*|docker.*|lo|flannel.*|cali.*|tunl.*|_nomatch)$'
    networks:
      - monitoring
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:9100/metrics || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    restart: unless-stopped
    privileged: true
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    networks:
      - monitoring
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 128M
    logging: *default-logging

  blackbox-exporter:
    image: prom/blackbox-exporter:latest
    restart: unless-stopped
    command:
      - --config.file=/config/blackbox.yml
    volumes:
      - ./blackbox-exporter:/config
    networks:
      - monitoring
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:9115/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging

  alertmanager:
    image: prom/alertmanager:latest
    restart: unless-stopped
    volumes:
      - ./alertmanager:/etc/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    networks:
      - monitoring
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:9093/-/healthy || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging: *default-logging

networks:
  ghost-internal:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.20.0.0/24
          ip_range: 172.20.0.0/24
          gateway: 172.20.0.1
    labels:
      description: "Internal network for Ghost services"
    driver_opts:
      encrypted: "true"

  monitoring:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.21.0.0/24
          ip_range: 172.21.0.0/24
          gateway: 172.21.0.1
    labels:
      description: "Internal network for monitoring services"
    driver_opts:
      encrypted: "true"

volumes:
  ghost-content:
    driver: local
  mysql-data:
    driver: local
  redis-data:
    driver: local
  grafana-data:
    driver: local
  prometheus-data:
    driver: local
  loki-data:
    driver: local
EOF
}

# Konfiguracja Nginx z rate limiting i zabezpieczeniami
setup_nginx() {
    log "Konfiguracja Nginx..."
    
    cat > /etc/nginx/conf.d/ghost.conf <<EOF
# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=ghost_limit:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=ghost_admin_limit:10m rate=5r/s;

# SSL configuration
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# Modern configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000" always;

# Additional security headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

# DDoS protection
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 5s 5s;
send_timeout 10s;

server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    # Root location
    location / {
        limit_req zone=ghost_limit burst=20 nodelay;
        proxy_pass http://ghost:2368;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Ghost Admin
    location /ghost {
        limit_req zone=ghost_admin_limit burst=10 nodelay;
        proxy_pass http://ghost:2368;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Additional security for admin
        add_header X-Robots-Tag "noindex, nofollow" always;
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
    }

    # Monitoring endpoints
    location /grafana/ {
        proxy_pass http://grafana:3000/;
        proxy_set_header Host \$host;
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    location /prometheus/ {
        proxy_pass http://prometheus:9090/;
        proxy_set_header Host \$host;
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    location /loki/ {
        proxy_pass http://loki:3100/;
        proxy_set_header Host \$host;
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 7d;
        add_header Cache-Control "public, no-transform";
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF
}
# Konfiguracja automatycznych backupów
setup_backup_system() {
    log "Konfiguracja systemu kopii zapasowych..."
    
    mkdir -p $INSTALL_DIR/scripts
    cat > $INSTALL_DIR/scripts/backup.sh <<EOF
#!/bin/bash

# Konfiguracja
BACKUP_DIR="$BACKUP_DIR"
RETENTION_DAYS=30
DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_LOG="$LOG_DIR/backup.log"

# Funkcja logowania
backup_log() {
    echo "[\$(date +'%Y-%m-%d %H:%M:%S')] \$1" | tee -a \$BACKUP_LOG
}

# Funkcja szyfrowania backupu
encrypt_backup() {
    local input_file="\$1"
    local output_file="\$input_file.enc"
    local encryption_key="\$(openssl rand -hex 32)"
    
    openssl enc -aes-256-gcm -salt -in "\$input_file" -out "\$output_file" -k "\$encryption_key"
    echo "\$encryption_key" > "\$input_file.key"
    chmod 600 "\$input_file.key"
    rm "\$input_file"
}

# Backup bazy danych
backup_database() {
    local backup_file="\$BACKUP_DIR/db_\$DATE.sql.gz"
    backup_log "Rozpoczęcie backupu bazy danych..."
    
    docker-compose exec -T db mysqldump \
        --single-transaction \
        --quick \
        --lock-tables=false \
        -u$DB_USER -p$MYSQL_PASSWORD $DB_NAME | gzip > "\$backup_file"
    
    if [ \$? -eq 0 ]; then
        backup_log "Backup bazy danych zakończony sukcesem"
        encrypt_backup "\$backup_file"
    else
        backup_log "Błąd podczas backupu bazy danych"
        return 1
    fi
}

# Backup contentu Ghost
backup_ghost_content() {
    local backup_file="\$BACKUP_DIR/content_\$DATE.tar.gz"
    backup_log "Rozpoczęcie backupu contentu..."
    
    tar -czf "\$backup_file" -C $INSTALL_DIR/ghost-content .
    
    if [ \$? -eq 0 ]; then
        backup_log "Backup contentu zakończony sukcesem"
        encrypt_backup "\$backup_file"
    else
        backup_log "Błąd podczas backupu contentu"
        return 1
    fi
}

# Czyszczenie starych backupów
cleanup_old_backups() {
    backup_log "Czyszczenie starych backupów..."
    
    find "\$BACKUP_DIR" -name "*.enc" -mtime +\$RETENTION_DAYS -delete
    find "\$BACKUP_DIR" -name "*.key" -mtime +\$RETENTION_DAYS -delete
    
    backup_log "Czyszczenie zakończone"
}

# Upload do zewnętrznego storage (przykład dla S3)
upload_to_remote_storage() {
    if [ -n "\$S3_BUCKET" ]; then
        backup_log "Rozpoczęcie uploadu do S3..."
        
        for file in "\$BACKUP_DIR"/*.enc "\$BACKUP_DIR"/*.key; do
            if [ -f "\$file" ]; then
                aws s3 cp "\$file" "s3://\$S3_BUCKET/backups/\$(basename \$file)"
                if [ \$? -eq 0 ]; then
                    backup_log "Upload \$(basename \$file) zakończony sukcesem"
                else
                    backup_log "Błąd podczas uploadu \$(basename \$file)"
                fi
            fi
        done
    fi
}

# Rotacja logów backupu
rotate_backup_logs() {
    if [ -f "\$BACKUP_LOG" ]; then
        if [ \$(stat -f%z "\$BACKUP_LOG") -gt 5242880 ]; then # 5MB
            mv "\$BACKUP_LOG" "\$BACKUP_LOG.\$DATE"
            gzip "\$BACKUP_LOG.\$DATE"
        fi
    fi
}

# Główna funkcja backup
main() {
    backup_log "Rozpoczęcie procesu backupu..."
    
    # Sprawdzenie przestrzeni dyskowej
    local free_space=\$(df -m "\$BACKUP_DIR" | awk 'NR==2 {print \$4}')
    if [ \$free_space -lt 5120 ]; then # 5GB
        backup_log "BŁĄD: Za mało miejsca na dysku (\${free_space}MB)"
        exit 1
    fi
    
    mkdir -p "\$BACKUP_DIR"
    
    # Wykonanie backupów
    backup_database && \
    backup_ghost_content && \
    cleanup_old_backups && \
    upload_to_remote_storage && \
    rotate_backup_logs
    
    local status=\$?
    if [ \$status -eq 0 ]; then
        backup_log "Backup zakończony sukcesem"
    else
        backup_log "Backup zakończony z błędami (status: \$status)"
        exit 1
    fi
}

# Uruchomienie z obsługą błędów
{
    flock -n 200 || {
        backup_log "BŁĄD: Inny proces backupu jest już uruchomiony"
        exit 1
    }
    
    main
} 200>/var/lock/ghost_backup.lock

EOF

    chmod +x $INSTALL_DIR/scripts/backup.sh
    
    # Dodanie do crontab
    cat > /etc/cron.d/ghost-backup <<EOF
# Backup codzienny o 3:00
0 3 * * * root $INSTALL_DIR/scripts/backup.sh

# Backup przyrostowy co 6 godzin
0 */6 * * * root $INSTALL_DIR/scripts/backup.sh incremental
EOF

    chmod 644 /etc/cron.d/ghost-backup
}

# Konfiguracja monitoringu bezpieczeństwa
setup_security_monitoring() {
    log "Konfiguracja monitoringu bezpieczeństwa..."
    
    # Instalacja i konfiguracja Fail2ban
    apt-get install -y fail2ban
    
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-badbots]
enabled = true
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[ghost-admin]
enabled = true
filter = ghost-admin
logpath = /var/log/nginx/access.log
maxretry = 3
EOF

    # Custom filter dla Ghost admin
    cat > /etc/fail2ban/filter.d/ghost-admin.conf <<EOF
[Definition]
failregex = ^<HOST> .* "POST /ghost/api/v3/admin/session" .* 401
ignoreregex =
EOF

    # Restart Fail2ban
    systemctl restart fail2ban
    
    # Konfiguracja auditd
    apt-get install -y auditd
    
    cat > /etc/audit/rules.d/ghost.rules <<EOF
# Monitoring zmian w plikach konfiguracyjnych
-w $INSTALL_DIR/docker-compose.yml -p wa -k ghost_config
-w /etc/nginx/conf.d/ghost.conf -p wa -k ghost_config
-w $MONITORING_DIR -p wa -k ghost_monitoring

# Monitoring dostępu do wrażliwych plików
-w $CREDENTIALS_FILE -p rwa -k ghost_credentials
-w ${CREDENTIALS_FILE}.key -p rwa -k ghost_credentials

# Monitoring prób dostępu do portów
-a exit,always -F arch=b64 -S bind -F a0=0x0.0.0.0 -F key=ghost_ports
EOF

    # Restart auditd
    service auditd restart
}

# Aktualizacja funkcji setup_auto_updates z obsługą błędów i powiadomieniami
setup_auto_updates() {
    log "Konfiguracja automatycznych aktualizacji..."
    
    cat > $INSTALL_DIR/scripts/update-ghost.sh <<EOF
#!/bin/bash

# Zmienne
SCRIPT_LOG="$LOG_DIR/update.log"
CURRENT_VERSION=\$(docker inspect ghost:latest | jq -r '.[0].Id')
ERROR_COUNT=0
MAX_RETRIES=3
UPDATE_LOCK="/var/lock/ghost_update.lock"

# Funkcja logowania
update_log() {
    echo "[\$(date +'%Y-%m-%d %H:%M:%S')] \$1" | tee -a \$SCRIPT_LOG
}

# Funkcja weryfikacji stanu aplikacji
check_ghost_health() {
    local max_attempts=12
    local attempt=1
    local wait_time=10
    
    update_log "Sprawdzanie stanu aplikacji..."
    
    while [ \$attempt -le \$max_attempts ]; do
        if curl -sSf https://$DOMAIN/ghost/api/v3/admin/site/ > /dev/null; then
            update_log "Aplikacja działa poprawnie"
            return 0
        fi
        
        update_log "Próba \$attempt/\$max_attempts - aplikacja nie odpowiada, czekam \${wait_time}s..."
        sleep \$wait_time
        attempt=\$((attempt + 1))
    done
    
    return 1
}

# Funkcja wykonująca backup przed aktualizacją
pre_update_backup() {
    update_log "Wykonywanie backupu przed aktualizacją..."
    
    $INSTALL_DIR/scripts/backup.sh pre-update
    if [ \$? -ne 0 ]; then
        update_log "BŁĄD: Backup przed aktualizacją nie powiódł się"
        return 1
    fi
    return 0
}

# Funkcja aktualizacji Ghost
update_ghost() {
    update_log "Rozpoczęcie aktualizacji Ghost..."
    
    # Backup przed aktualizacją
    pre_update_backup || return 1
    
    # Pobranie najnowszego obrazu
    update_log "Pobieranie najnowszego obrazu Ghost..."
    docker pull ghost:latest
    if [ \$? -ne 0 ]; then
        update_log "BŁĄD: Nie udało się pobrać najnowszego obrazu"
        return 1
    fi
    
    # Zapisanie starego i nowego hasha obrazu
    local old_hash=\$CURRENT_VERSION
    local new_hash=\$(docker inspect ghost:latest | jq -r '.[0].Id')
    
    # Jeśli nie ma zmian w obrazie, kończymy
    if [ "\$old_hash" = "\$new_hash" ]; then
        update_log "Brak nowych aktualizacji"
        return 0
    fi
    
    # Restart z nowym obrazem
    update_log "Restart Ghost z nowym obrazem..."
    cd $INSTALL_DIR
    docker-compose up -d --force-recreate ghost
    
    # Sprawdzenie stanu po aktualizacji
    if ! check_ghost_health; then
        update_log "BŁĄD: Ghost nie działa poprawnie po aktualizacji"
        return 1
    fi
    
    # Zapisanie informacji o aktualizacji
    update_log "Aktualizacja zakończona pomyślnie"
    echo "\$(date +'%Y-%m-%d %H:%M:%S') \$old_hash -> \$new_hash" >> "$LOG_DIR/update_history.log"
    
    return 0
}

# Funkcja rollback
perform_rollback() {
    update_log "Rozpoczęcie procedury rollback..."
    
    # Przywrócenie poprzedniej wersji
    docker tag \$CURRENT_VERSION ghost:latest
    docker-compose up -d --force-recreate ghost
    
    # Sprawdzenie stanu po rollback
    if check_ghost_health; then
        update_log "Rollback zakończony pomyślnie"
        return 0
    else
        update_log "BŁĄD: Rollback nie powiódł się"
        return 1
    fi
}

# Funkcja wysyłająca powiadomienia
send_notification() {
    local status=\$1
    local message=\$2
    
    # Slack webhook (jeśli skonfigurowany)
    if [ -n "\$SLACK_WEBHOOK_URL" ]; then
        curl -X POST -H 'Content-type: application/json' \\
            --data "{\\"text\\":\\"\$message\\"}" \\
            \$SLACK_WEBHOOK_URL
    fi
    
    # Email notification
    if [ -n "\$ADMIN_EMAIL" ]; then
        echo "\$message" | mail -s "Ghost Update [\$status] - $DOMAIN" \$ADMIN_EMAIL
    fi
}

# Główna logika z retries
main() {
    # Sprawdzenie czy inny proces aktualizacji nie jest uruchomiony
    if ! mkdir "\$UPDATE_LOCK" 2>/dev/null; then
        update_log "BŁĄD: Inny proces aktualizacji jest już uruchomiony"
        exit 1
    fi
    
    trap 'rm -rf "\$UPDATE_LOCK"' EXIT
    
    while [ \$ERROR_COUNT -lt \$MAX_RETRIES ]; do
        if update_ghost; then
            send_notification "SUCCESS" "Ghost został pomyślnie zaktualizowany"
            exit 0
        else
            ERROR_COUNT=\$((ERROR_COUNT + 1))
            update_log "Próba aktualizacji \$ERROR_COUNT nie powiodła się"
            
            if [ \$ERROR_COUNT -eq \$MAX_RETRIES ]; then
                update_log "Osiągnięto maksymalną liczbę prób, wykonywanie rollback..."
                
                if perform_rollback; then
                    send_notification "ROLLBACK" "Aktualizacja Ghost nie powiodła się, wykonano rollback"
                else
                    send_notification "CRITICAL" "Aktualizacja Ghost nie powiodła się, rollback również nie powiódł się!"
                fi
                exit 1
            fi
            
            sleep 60
        fi
    done
}

# Rotacja logów
if [ -f "\$SCRIPT_LOG" ]; then
    if [ \$(stat -f%z "\$SCRIPT_LOG") -gt 5242880 ]; then # 5MB
        mv "\$SCRIPT_LOG" "\$SCRIPT_LOG.\$(date +%Y%m%d)"
        gzip "\$SCRIPT_LOG.\$(date +%Y%m%d)"
    fi
fi

# Uruchomienie głównej funkcji
main
EOF

    chmod +x $INSTALL_DIR/scripts/update-ghost.sh
    
    # Dodanie do crontab
    cat > /etc/cron.d/ghost-updates <<EOF
# Aktualizacja w każdą niedzielę o 3:00
0 3 * * 0 root $INSTALL_DIR/scripts/update-ghost.sh

# Sprawdzanie dostępności aktualizacji codziennie
0 */12 * * * root docker pull ghost:latest > /dev/null 2>&1
EOF

    chmod 644 /etc/cron.d/ghost-updates
}

# Konfiguracja monitorowania wydajności
setup_performance_monitoring() {
    log "Konfiguracja monitorowania wydajności..."

