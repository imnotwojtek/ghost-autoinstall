# Funkcje pomocnicze dla zarządzania Ghost

# Funkcja aktualizacji Ghost
update_ghost() {
    log "INFO" "Rozpoczęcie aktualizacji Ghost..."
    
    # Utworzenie backupu przed aktualizacją
    /usr/local/bin/ghost-backup.sh || {
        log "ERROR" "Nie można utworzyć backupu przed aktualizacją"
        return 1
    }
    
    # Pobranie aktualnej wersji
    local current_version
    current_version=$(cd "$GHOST_DIR" && npm list ghost | grep ghost@ | cut -d'@' -f2)
    
    # Pobranie najnowszej wersji
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/TryGhost/Ghost/releases/latest | grep tag_name | cut -d '"' -f 4)
    
    if [[ "$current_version" == "$latest_version" ]]; then
        log "INFO" "Ghost jest aktualny (wersja ${current_version})"
        return 0
    fi
    
    log "INFO" "Aktualizacja Ghost z wersji ${current_version} do ${latest_version}"
    
    # Zatrzymanie Ghost
    systemctl stop ghost
    
    # Aktualizacja
    cd "$GHOST_DIR" || exit 1
    npm install ghost@latest --save
    
    # Uruchomienie Ghost
    systemctl start ghost
    
    # Weryfikacja
    local timeout=30
    local counter=0
    while ! curl -s http://localhost:2368 > /dev/null; do
        sleep 1
        counter=$((counter + 1))
        if ((counter >= timeout)); then
            log "ERROR" "Timeout podczas uruchamiania Ghost po aktualizacji"
            return 1
        fi
    done
    
    log "INFO" "Aktualizacja zakończona pomyślnie"
    return 0
}

# Funkcja zarządzania certyfikatami SSL
manage_ssl() {
    local command="$1"
    local domain="${2:-$DOMAIN}"
    
    case "$command" in
        "renew")
            log "INFO" "Odnawianie certyfikatu SSL dla $domain"
            certbot renew --nginx --domain "$domain"
            ;;
        "create")
            log "INFO" "Tworzenie nowego certyfikatu SSL dla $domain"
            certbot --nginx --domain "$domain" --agree-tos --email "$ADMIN_EMAIL" -n
            ;;
        "status")
            local cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
            if [[ -f "$cert_path" ]]; then
                openssl x509 -in "$cert_path" -text -noout
            else
                log "ERROR" "Nie znaleziono certyfikatu dla $domain"
                return 1
            fi
            ;;
        *)
            log "ERROR" "Nieznane polecenie: $command"
            echo "Dostępne polecenia: renew, create, status"
            return 1
            ;;
    esac
}

# Funkcja czyszczenia systemu
cleanup_system() {
    log "INFO" "Rozpoczęcie czyszczenia systemu..."
    
    # Czyszczenie logów
    find /var/log -type f -name "*.gz" -delete
    find /var/log -type f -name "*.old" -delete
    
    # Czyszczenie cache
    apt-get clean
    apt-get autoremove -y
    
    # Czyszczenie starych backupów
    find "$BACKUP_DIR" -type f -mtime +30 -delete
    
    # Czyszczenie nieużywanych obrazów Dockera (jeśli zainstalowany)
    if command -v docker >/dev/null 2>&1; then
        docker system prune -af
    fi
    
    # Czyszczenie pamięci podręcznej npm
    npm cache clean --force
    
    # Czyszczenie temporary files
    find /tmp -type f -atime +10 -delete
    find "$TEMP_DIR" -type f -mtime +1 -delete
    
    log "INFO" "Czyszczenie systemu zakończone"
}

# Funkcja diagnostyczna
diagnose_system() {
    log "INFO" "Rozpoczęcie diagnostyki systemu..."
    
    local report_file="/tmp/ghost_diagnostic_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=== Ghost Diagnostic Report ==="
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo
        
        echo "=== System Information ==="
        uname -a
        echo
        
        echo "=== Memory Usage ==="
        free -h
        echo
        
        echo "=== Disk Usage ==="
        df -h
        echo
        
        echo "=== Process List ==="
        ps aux | grep -E 'ghost|nginx|mysql|node'
        echo
        
        echo "=== Ghost Status ==="
        systemctl status ghost
        echo
        
        echo "=== Nginx Status ==="
        systemctl status nginx
        echo
        
        echo "=== MySQL Status ==="
        systemctl status mysql
        echo
        
        echo "=== Recent Logs ==="
        echo "--- Ghost Logs ---"
        tail -n 50 /var/log/ghost/application.log
        echo
        
        echo "--- Nginx Error Logs ---"
        tail -n 50 /var/log/nginx/error.log
        echo
        
        echo "--- MySQL Error Logs ---"
        tail -n 50 /var/log/mysql/error.log
        echo
        
        echo "=== Security Checks ==="
        echo "--- Failed SSH Attempts ---"
        grep "Failed password" /var/log/auth.log | tail -n 10
        echo
        
        echo "--- Fail2ban Status ---"
        fail2ban-client status
        echo
        
        echo "=== Network Information ==="
        netstat -tulpn
        echo
        
        echo "=== Certificate Information ==="
        openssl x509 -in "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" -text -noout 2>/dev/null
        
    } > "$report_file"
    
    log "INFO" "Raport diagnostyczny zapisany w $report_file"
    
    # Wysyłanie raportu mailem
    if [[ -f "$report_file" ]]; then
        /usr/local/bin/send-notification \
            "System Diagnostic Report" \
            "$(cat "$report_file")" \
            "normal"
    fi
}

# Dokumentacja użycia
show_help() {
    cat << EOF
Ghost Installation and Management Script v${SCRIPT_VERSION}

Użycie: $0 [opcja] [argumenty]

Opcje:
    install             Pełna instalacja Ghost
    update             Aktualizacja Ghost do najnowszej wersji
    ssl <command>      Zarządzanie certyfikatami SSL (create|renew|status)
    cleanup            Czyszczenie systemu
    diagnose           Diagnostyka systemu
    verify             Weryfikacja instalacji
    backup             Wykonanie backupu
    help               Wyświetlenie tej pomocy

Przykłady:
    $0 install                     # Instalacja Ghost
    $0 update                      # Aktualizacja Ghost
    $0 ssl renew                   # Odnowienie certyfikatu SSL
    $0 diagnose                    # Uruchomienie diagnostyki

Zmienne środowiskowe:
    DOMAIN              Domena dla instalacji Ghost
    ADMIN_EMAIL         Email administratora
    VERBOSE            Włączenie trybu verbose (1/0)

EOF
}

# Rozszerzenie głównej funkcji o obsługę parametrów
main() {
    local command="${1:-}"
    shift || true
    
    case "$command" in
        "install")
            log "INFO" "Rozpoczęcie instalacji Ghost v${SCRIPT_VERSION}..."
            install_ghost
            ;;
        "update")
            update_ghost
            ;;
        "ssl")
            manage_ssl "$@"
            ;;
        "cleanup")
            cleanup_system
            ;;
        "diagnose")
            diagnose_system
            ;;
        "verify")
            verify_installation
            ;;
        "backup")
            /usr/local/bin/ghost-backup.sh
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        *)
            log "ERROR" "Nieznane polecenie: $command"
            show_help
            exit 1
            ;;
    esac
}

# Uruchomienie skryptu z obsługą parametrów
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi    # Test systemu powiadomień
    /usr/local/bin/send-notification \
        "System Installation" \
        "Ghost monitoring system has been configured successfully" \
        "normal"
}

# Funkcja weryfikacji instalacji
verify_installation() {
    log "INFO" "Weryfikacja instalacji..."
    local status=0

    # Tablica testów
    declare -A checks=(
        ["Vault status"]="vault status"
        ["MariaDB status"]="systemctl is-active mariadb"
        ["Nginx status"]="systemctl is-active nginx"
        ["Nginx config test"]="nginx -t"
        ["Prometheus status"]="systemctl is-active prometheus"
        ["Node Exporter status"]="systemctl is-active node_exporter"
        ["Fail2ban status"]="systemctl is-active fail2ban"
        ["NFTables status"]="systemctl is-active nftables"
        ["Postfix status"]="systemctl is-active postfix"
        ["Audit status"]="systemctl is-active auditd"
    )

    # Weryfikacja certyfikatów SSL
    check_ssl() {
        local domain="$1"
        local cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
        
        if [[ ! -f "$cert_path" ]]; then
            echo "Brak certyfikatu SSL"
            return 1
        fi
        
        local expiry
        expiry=$(openssl x509 -enddate -noout -in "$cert_path" | cut -d= -f2)
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry" +%s)
        local now_epoch
        now_epoch=$(date +%s)
        local days_left
        days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        
        if (( days_left < 30 )); then
            echo "Certyfikat SSL wygasa za $days_left dni"
            return 1
        fi
        
        return 0
    }

    # Weryfikacja portów
    check_ports() {
        local required_ports=(80 443 2368 9090 9100)
        local errors=0
        
        for port in "${required_ports[@]}"; do
            if ! netstat -tuln | grep -q ":${port} "; then
                echo "Port $port nie jest otwarty"
                errors=$((errors + 1))
            fi
        done
        
        return "$errors"
    }

    # Weryfikacja uprawnień
    check_permissions() {
        local errors=0
        
        # Sprawdzenie krytycznych katalogów
        local directories=(
            "$GHOST_DIR:ghost:ghost:750"
            "$SECURE_KEY_DIR:root:root:700"
            "$BACKUP_DIR:root:root:700"
            "$LOG_DIR:syslog:adm:750"
        )
        
        for dir_spec in "${directories[@]}"; do
            IFS=: read -r dir owner group perm <<< "$dir_spec"
            
            if [[ ! -d "$dir" ]]; then
                echo "Katalog $dir nie istnieje"
                errors=$((errors + 1))
                continue
            fi
            
            local current_owner
            current_owner=$(stat -c %U "$dir")
            local current_group
            current_group=$(stat -c %G "$dir")
            local current_perm
            current_perm=$(stat -c %a "$dir")
            
            if [[ "$current_owner" != "$owner" ]] || 
               [[ "$current_group" != "$group" ]] || 
               [[ "$current_perm" != "$perm" ]]; then
                echo "Nieprawidłowe uprawnienia dla $dir"
                echo "Oczekiwane: $owner:$group:$perm"
                echo "Aktualne: $current_owner:$current_group:$current_perm"
                errors=$((errors + 1))
            fi
        done
        
        return "$errors"
    }

    # Wykonanie wszystkich testów
    log "INFO" "Sprawdzanie statusu usług..."
    for test_name in "${!checks[@]}"; do
        if ! eval "${checks[$test_name]}" > /dev/null 2>&1; then
            log "ERROR" "Test '$test_name' nie powiódł się"
            status=$((status + 1))
        else
            log "INFO" "Test '$test_name' zakończony pomyślnie"
        fi
    done

    log "INFO" "Sprawdzanie certyfikatów SSL..."
    if ! check_ssl "$DOMAIN"; then
        log "ERROR" "Weryfikacja SSL nie powiodła się"
        status=$((status + 1))
    fi

    log "INFO" "Sprawdzanie portów..."
    if ! check_ports; then
        log "ERROR" "Weryfikacja portów nie powiodła się"
        status=$((status + 1))
    fi

    log "INFO" "Sprawdzanie uprawnień..."
    if ! check_permissions; then
        log "ERROR" "Weryfikacja uprawnień nie powiodła się"
        status=$((status + 1))
    fi

    # Sprawdzenie backupu
    log "INFO" "Testowanie systemu backupu..."
    if ! /usr/local/bin/ghost-backup.sh; then
        log "ERROR" "Test backupu nie powiódł się"
        status=$((status + 1))
    fi

    return "$status"
}

# Główna funkcja instalacyjna
install_ghost() {
    log "INFO" "Rozpoczęcie instalacji Ghost..."
    
    # Przygotowanie środowiska
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR" || exit 1
    
    # Pobranie najnowszej wersji Ghost
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/TryGhost/Ghost/releases/latest | grep tag_name | cut -d '"' -f 4)
    
    log "INFO" "Pobieranie Ghost v${latest_version}..."
    curl -L "https://github.com/TryGhost/Ghost/releases/download/${latest_version}/Ghost-$(echo "$latest_version" | cut -d 'v' -f2).zip" -o ghost.zip
    
    unzip ghost.zip -d "$GHOST_DIR"
    
    # Instalacja zależności
    cd "$GHOST_DIR" || exit 1
    npm install --production
    
    # Konfiguracja Ghost
    local db_creds
    db_creds=$(vault kv get -format=json secret/ghost/db)
    local admin_creds
    admin_creds=$(vault kv get -format=json secret/ghost/admin)
    
    cat > config.production.json << EOF
{
    "url": "https://${DOMAIN}",
    "server": {
        "host": "127.0.0.1",
        "port": 2368
    },
    "database": {
        "client": "mysql",
        "connection": {
            "host": "localhost",
            "port": 3306,
            "user": "$(echo "$db_creds" | jq -r '.data.data.user')",
            "password": "$(echo "$db_creds" | jq -r '.data.data.pass')",
            "database": "$(echo "$db_creds" | jq -r '.data.data.name')"
        },
        "pool": {
            "min": 2,
            "max": 10
        }
    },
    "mail": {
        "transport": "SMTP",
        "options": {
            "host": "localhost",
            "port": 25,
            "secure": false
        }
    },
    "process": "systemd",
    "logging": {
        "level": "info",
        "rotation": {
            "enabled": true,
            "period": "1d",
            "count": 10
        },
        "transports": ["file", "stdout"]
    },
    "paths": {
        "contentPath": "/var/www/ghost/content"
    }
}
EOF

    # Konfiguracja systemd
    cat > /etc/systemd/system/ghost.service << EOF
[Unit]
Description=Ghost Blog
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/var/www/ghost
Environment="NODE_ENV=production"
ExecStart=/usr/bin/node current/index.js
Restart=always
RestartSec=10
SyslogIdentifier=ghost

# Limity bezpieczeństwa
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadOnlyDirectories=/
ReadWriteDirectories=/var/www/ghost/content
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

    # Tworzenie użytkownika ghost
    useradd -r -s /bin/false ghost
    chown -R ghost:ghost "$GHOST_DIR"
    
    # Uruchomienie Ghost
    systemctl daemon-reload
    systemctl enable ghost
    systemctl start ghost
    
    # Oczekiwanie na uruchomienie Ghost
    local timeout=30
    local counter=0
    while ! curl -s http://localhost:2368 > /dev/null; do
        sleep 1
        counter=$((counter + 1))
        if ((counter >= timeout)); then
            log "ERROR" "Timeout podczas uruchamiania Ghost"
            return 1
        fi
    done
}

# Główna funkcja
main() {
    log "INFO" "Rozpoczęcie instalacji Ghost v${SCRIPT_VERSION}..."
    
    # Inicjalizacja blokady
    acquire_lock "ghost-install"
    
    # Wykonanie wszystkich kroków instalacji
    setup_logging
    validate_environment
    check_system_requirements
    install_required_packages
    setup_secure_filesystem
    setup_vault
    generate_secure_credentials
    setup_kernel_security
    setup_mariadb
    setup_nginx
    setup_firewall
    install_ghost
    setup_backups
    setup_monitoring
    setup_system_audit
    setup_notifications
    setup_auto_updates
    
    # Weryfikacja instalacji
    if verify_installation; then
        log "INFO" "Instalacja zakończona pomyślnie"
        /usr/local/bin/send-notification \
            "Installation Complete" \
            "Ghost has been successfully installed and configured on ${DOMAIN}" \
            "normal"
    else
        log "ERROR" "Instalacja zakończona z błędami"
        /usr/local/bin/send-notification \
            "Installation Failed" \
            "Ghost installation on ${DOMAIN} completed with errors. Please check logs." \
            "high"
        exit 1
    fi
    
    # Zwolnienie blokady
    release_lock "ghost-install"
}

# Uruchomienie skryptu
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi/var/lib/apt/listchanges.db
only_on_upgrade=false
which=news
EOF

    # Włączenie automatycznych aktualizacji
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades
}

# Funkcja konfigurująca zabezpieczenia kernela
setup_kernel_security() {
    log "INFO" "Konfiguracja zabezpieczeń kernela..."
    
    # Konfiguracja parametrów sysctl
    cat > /etc/sysctl.d/99-security.conf << EOF
# Ochrona przed atakami sieciowymi
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6 zabezpieczenia
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ochrona przed atakami na pamięć
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.panic = 60
kernel.panic_on_oops = 60

# Limity systemowe
fs.file-max = 65535
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Buforowanie i pamięć
vm.swappiness = 10
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5
vm.mmap_min_addr = 65536
vm.overcommit_memory = 0
vm.panic_on_oom = 0
vm.oom_kill_allocating_task = 0
EOF

    # Załadowanie nowych ustawień
    sysctl -p /etc/sysctl.d/99-security.conf
    
    # Zabezpieczenie modułów kernela
    cat > /etc/modprobe.d/blacklist-dangerous.conf << EOF
# Protokoły rzadko używane
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false

# Systemy plików egzotyczne
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false

# Protokoły przestarzałe
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
EOF
}

# Funkcja konfigurująca firewall
setup_firewall() {
    log "INFO" "Konfiguracja firewalla..."
    
    # Instalacja i konfiguracja nftables
    cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Dozwolony localhost
        iif lo accept
        
        # Ustalone połączenia
        ct state established,related accept
        
        # ICMP/ICMPv6
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, time-exceeded, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-router-solicit } accept
        
        # SSH (z rate limitingiem)
        tcp dport ssh ct state new limit rate 10/minute accept
        
        # HTTP/HTTPS
        tcp dport { http, https } accept
        udp dport https accept  # QUIC/HTTP3
        
        # Ghost
        tcp dport 2368 accept
        
        # Node Exporter dla Prometheus
        ip saddr 127.0.0.1 tcp dport 9100 accept
        
        # Logowanie odrzuconych
        counter drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# Tablica dla ochrony przed skanowaniem portów
table inet portscan {
    set flood_ports {
        type inet_service
        flags dynamic,timeout
        timeout 60s
    }
    
    chain scan_guard {
        type filter hook input priority -10; policy accept;
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg counter drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop
        tcp flags syn tcp dport != 22 add @flood_ports { tcp dport limit rate over 50/minute } counter drop
    }
}
EOF

    # Włączenie i uruchomienie nftables
    systemctl enable nftables
    systemctl restart nftables
    
    # Konfiguracja fail2ban z nftables
    cat > /etc/fail2ban/action.d/nftables-common.local << EOF
[Definition]
actionstart = nft add table inet fail2ban
              nft add chain inet fail2ban blacklist
              nft add chain inet fail2ban input { type filter hook input priority -1 \; policy accept \; }
              nft add rule inet fail2ban input ip saddr @blacklist counter drop

actionstop = nft delete table inet fail2ban

actionban = nft add element inet fail2ban blacklist { <ip> }

actionunban = nft delete element inet fail2ban blacklist { <ip> }
EOF
}

# Funkcja konfigurująca audyt systemowy
setup_system_audit() {
    log "INFO" "Konfiguracja audytu systemowego..."
    
    # Konfiguracja auditd
    cat > /etc/audit/rules.d/ghost.rules << EOF
# Monitorowanie zmian w plikach konfiguracyjnych
-w /etc/ghost/ -p wa -k ghost_config
-w /etc/nginx/ -p wa -k nginx_config
-w /etc/mysql/ -p wa -k mysql_config

# Monitorowanie dostępu do plików Ghost
-w ${GHOST_DIR}/config.production.json -p rwa -k ghost_config_access
-w ${GHOST_DIR}/content/data/ -p wa -k ghost_data_access
-w ${GHOST_DIR}/content/images/ -p wa -k ghost_image_access

# Monitorowanie wykonywania poleceń sudo
-a exit,always -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k sudo_commands

# Monitorowanie zmian w użytkownikach i grupach
-w /etc/passwd -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/shadow -p wa -k shadow_modification
-w /etc/sudoers -p wa -k sudoers_modification

# Monitorowanie operacji montowania
-a always,exit -F arch=b64 -S mount -S umount2 -k mount_operations

# Monitorowanie nieudanych prób logowania
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/nginx/access.log -p wa -k nginx_access
-w /var/log/nginx/error.log -p wa -k nginx_error
-w /var/log/mysql/error.log -p wa -k mysql_error

# Monitorowanie procesów Ghost
-w /usr/bin/node -p x -k ghost_execution
EOF

    # Restart auditd
    systemctl restart auditd
    
    # Konfiguracja rsyslog dla lepszego logowania
    cat > /etc/rsyslog.d/ghost.conf << EOF
# Ghost aplikacja
if \$programname == 'ghost' then /var/log/ghost/application.log
& stop

# Nginx
if \$programname == 'nginx' then /var/log/nginx/full.log
& stop

# MariaDB
if \$programname == 'mysqld' then /var/log/mysql/full.log
& stop

# Bezpieczeństwo
if \$programname contains 'fail2ban' then /var/log/security.log
if \$programname contains 'auditd' then /var/log/security.log
if \$programname contains 'nftables' then /var/log/security.log
& stop
EOF

    # Restart rsyslog
    systemctl restart rsyslog
    
    # Konfiguracja logrotate dla nowych logów
    cat > /etc/logrotate.d/ghost-security << EOF
/var/log/security.log
/var/log/ghost/application.log
/var/log/nginx/full.log
/var/log/mysql/full.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
EOF
}

# System powiadomień
setup_notifications() {
    log "INFO" "Konfiguracja systemu powiadomień..."
    
    # Instalacja i konfiguracja postfix dla powiadomień email
    debconf-set-selections <<< "postfix postfix/mailname string ${DOMAIN}"
    debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
    apt-get install -y postfix

    # Konfiguracja Postfix
    cat > /etc/postfix/main.cf << EOF
# Podstawowa konfiguracja
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no

# TLS configuration
smtpd_tls_cert_file=/etc/letsencrypt/live/${DOMAIN}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/${DOMAIN}/privkey.pem
smtpd_use_tls=yes
smtpd_tls_auth_only = yes
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
tls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

# Zabezpieczenia
smtpd_helo_required = yes
smtpd_helo_restrictions = permit_mynetworks,reject_invalid_helo_hostname,reject_non_fqdn_helo_hostname
smtpd_sender_restrictions = reject_non_fqdn_sender,reject_unknown_sender_domain
smtpd_recipient_restrictions = reject_non_fqdn_recipient,reject_unknown_recipient_domain,permit_mynetworks,reject_unauth_destination
disable_vrfy_command = yes

# Limity
message_size_limit = 10485760
mailbox_size_limit = 0

# Sieć
myhostname = ${DOMAIN}
mydomain = ${DOMAIN}
myorigin = \$mydomain
inet_interfaces = loopback-only
inet_protocols = ipv4
mydestination = \$myhostname, localhost.\$mydomain, localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
EOF

    # Script powiadomień
    cat > /usr/local/bin/send-notification << 'EOF'
#!/bin/bash
set -euo pipefail

SUBJECT="$1"
MESSAGE="$2"
PRIORITY="${3:-normal}"  # normal, high, low

# Formatowanie wiadomości
FORMATTED_MESSAGE="
Priority: ${PRIORITY}
Date: $(date)
Host: $(hostname)

${MESSAGE}

---
This is an automated message from Ghost monitoring system.
"

# Wysyłanie emaila
echo "${FORMATTED_MESSAGE}" | mailx -s "[Ghost] ${SUBJECT}" \
    -r "ghost-monitor@${DOMAIN}" "${ADMIN_EMAIL}"

# Jeśli priorytet wysoki, wysyłamy też do syslog
if [[ "${PRIORITY}" == "high" ]]; then
    logger -t ghost-monitor -p daemon.alert "${SUBJECT}: ${MESSAGE}"
fi
EOF
    chmod +x /usr/local/bin/send-notification

    # Test systemu powiadom    # Testowanie konfiguracji
    if ! nginx -t; then
        error_log "Błędna konfiguracja Nginx"
    fi
    
    systemctl restart nginx
}

# Funkcja konfigurująca backupy
setup_backups() {
    log "INFO" "Konfiguracja systemu backupów..."
    
    local backup_script="/usr/local/bin/ghost-backup.sh"
    
    # Tworzenie skryptu backupu
    cat > "$backup_script" << 'EOF'
#!/bin/bash
set -euo pipefail

# Konfiguracja
BACKUP_DIR="/var/backups/ghost"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7
MIN_SPACE_KB=$((5 * 1024 * 1024))  # 5GB w KB

# Pobranie poświadczeń z Vault
DB_CREDS=$(vault kv get -format=json secret/ghost/db)
DB_NAME=$(echo "$DB_CREDS" | jq -r '.data.data.name')
DB_USER=$(echo "$DB_CREDS" | jq -r '.data.data.user')
DB_PASS=$(echo "$DB_CREDS" | jq -r '.data.data.pass')
ENCRYPTION_KEY=$(vault kv get -format=json secret/ghost/encryption | jq -r '.data.data.key')

# Funkcja sprawdzająca przestrzeń
check_disk_space() {
    local available_space
    available_space=$(df "$BACKUP_DIR" | awk 'NR==2 {print $4}')
    if ((available_space < MIN_SPACE_KB)); then
        echo "BŁĄD: Za mało miejsca na dysku (dostępne: ${available_space}KB, wymagane: ${MIN_SPACE_KB}KB)" >&2
        exit 1
    fi
}

# Funkcja backupu z kompresją przyrostową
backup_files() {
    local target="$BACKUP_DIR/ghost_files_$DATE.tar.zst"
    local last_backup
    
    # Znajdź ostatni backup
    last_backup=$(find "$BACKUP_DIR" -name "ghost_files_*.tar.zst" -type f -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2)
    
    if [[ -n "$last_backup" ]]; then
        # Backup przyrostowy
        tar --zstd -cf "$target" \
            --newer-mtime="$last_backup" \
            --exclude="*.log" \
            --exclude="node_modules" \
            /var/www/ghost
    else
        # Pełny backup
        tar --zstd -cf "$target" \
            --exclude="*.log" \
            --exclude="node_modules" \
            /var/www/ghost
    fi
    
    # Szyfrowanie
    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in "$target" -out "${target}.enc" -pass env:ENCRYPTION_KEY
    rm "$target"
}

# Funkcja backupu bazy danych
backup_database() {
    local target="$BACKUP_DIR/ghost_db_$DATE.sql.zst"
    
    # Backup z kompresją zstd
    mysqldump --single-transaction --quick --lock-tables=false \
        -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" | \
        zstd -19 -T0 > "$target"
    
    # Szyfrowanie
    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in "$target" -out "${target}.enc" -pass env:ENCRYPTION_KEY
    rm "$target"
}

# Funkcja weryfikacji backupu
verify_backup() {
    local file="$1"
    local temp_file
    temp_file=$(mktemp)
    
    if ! openssl enc -aes-256-cbc -d -salt -pbkdf2 \
        -in "$file" -pass env:ENCRYPTION_KEY -out "$temp_file" 2>/dev/null; then
        echo "BŁĄD: Backup $file jest uszkodzony!" >&2
        rm "$temp_file"
        return 1
    fi
    
    rm "$temp_file"
    return 0
}

# Główna funkcja backupu
main() {
    # Sprawdzenie blokady
    local lock_file="/var/run/ghost_backup.lock"
    if ! mkdir "$lock_file" 2>/dev/null; then
        echo "BŁĄD: Inny backup jest w trakcie wykonywania" >&2
        exit 1
    fi
    trap 'rm -rf "$lock_file"' EXIT
    
    # Sprawdzenie przestrzeni
    check_disk_space
    
    # Wykonanie backupów
    backup_database &
    backup_files &
    wait
    
    # Weryfikacja
    local status=0
    for file in "$BACKUP_DIR"/*_"$DATE"*.enc; do
        if ! verify_backup "$file"; then
            status=1
        fi
    done
    
    # Czyszczenie starych backupów
    find "$BACKUP_DIR" -type f -mtime +"$RETENTION_DAYS" -delete
    
    # Raport
    if [[ $status -eq 0 ]]; then
        echo "Backup zakończony pomyślnie - $(date)"
    else
        echo "BŁĄD: Backup zakończony z błędami - $(date)" >&2
        exit 1
    fi
}

main "$@"
EOF

    chmod 700 "$backup_script"
    
    # Konfiguracja harmonogramu backupów
    cat > /etc/cron.d/ghost-backup << EOF
0 2 * * * root /usr/local/bin/ghost-backup.sh 2>&1 | logger -t ghost-backup
EOF
    
    chmod 644 /etc/cron.d/ghost-backup
}

# Funkcja konfigurująca monitoring
setup_monitoring() {
    log "INFO" "Konfiguracja monitoringu..."
    
    # Instalacja i konfiguracja Prometheus
    local prom_version="$PROMETHEUS_VERSION"
    local node_exp_version="$NODE_EXPORTER_VERSION"
    
    # Pobieranie i instalacja Prometheus
    curl -L "https://github.com/prometheus/prometheus/releases/download/v${prom_version}/prometheus-${prom_version}.linux-amd64.tar.gz" | \
        tar xz -C /tmp/
    
    mv "/tmp/prometheus-${prom_version}.linux-amd64/prometheus" /usr/local/bin/
    mv "/tmp/prometheus-${prom_version}.linux-amd64/promtool" /usr/local/bin/
    
    # Konfiguracja Prometheus
    mkdir -p /etc/prometheus
    cat > /etc/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - localhost:9093

rule_files:
  - "/etc/prometheus/rules/*.yml"

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
  
  - job_name: 'ghost'
    static_configs:
      - targets: ['localhost:2368']
    
  - job_name: 'nginx'
    static_configs:
      - targets: ['localhost:9113']
    
  - job_name: 'mysql'
    static_configs:
      - targets: ['localhost:9104']
EOF

    # Reguły alertów
    mkdir -p /etc/prometheus/rules
    cat > /etc/prometheus/rules/ghost.yml << EOF
groups:
  - name: ghost_alerts
    rules:
      - alert: HighCPUUsage
        expr: rate(process_cpu_seconds_total[5m]) > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High CPU usage on Ghost instance
          
      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes / process_heap_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High memory usage on Ghost instance
          
      - alert: DiskSpaceLow
        expr: node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} < 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: Low disk space on Ghost server
EOF

    # Instalacja i konfiguracja Node Exporter
    curl -L "https://github.com/prometheus/node_exporter/releases/download/v${node_exp_version}/node_exporter-${node_exp_version}.linux-amd64.tar.gz" | \
        tar xz -C /tmp/
    
    mv "/tmp/node_exporter-${node_exp_version}.linux-amd64/node_exporter" /usr/local/bin/
    
    # Konfiguracja usług systemd
    cat > /etc/systemd/system/prometheus.service << EOF
[Unit]
Description=Prometheus Monitoring System
Documentation=https://prometheus.io/docs/introduction/overview/
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file=/etc/prometheus/prometheus.yml \
    --storage.tsdb.path=/var/lib/prometheus \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries \
    --web.listen-address=localhost:9090 \
    --web.external-url=http://localhost:9090 \
    --storage.tsdb.retention.time=15d \
    --web.enable-lifecycle

SyslogIdentifier=prometheus
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/node_exporter.service << EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
    --collector.systemd \
    --collector.processes \
    --web.listen-address=localhost:9100

SyslogIdentifier=node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Tworzenie użytkowników systemowych
    useradd --no-create-home --shell /bin/false prometheus
    useradd --no-create-home --shell /bin/false node_exporter
    
    # Tworzenie katalogów i ustawianie uprawnień
    mkdir -p /var/lib/prometheus
    chown prometheus:prometheus /var/lib/prometheus
    
    # AIDE (System monitorowania integralności plików)
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    # Konfiguracja automatycznych skanów AIDE
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
aide --check | mailx -s "AIDE Daily Check Report" "${ADMIN_EMAIL}"
EOF
    chmod 700 /etc/cron.daily/aide-check
    
    # Logwatch
    cat > /etc/cron.daily/00logwatch << 'EOF'
#!/bin/bash
/usr/sbin/logwatch --output mail --mailto "${ADMIN_EMAIL}" --detail high
EOF
    chmod 700 /etc/cron.daily/00logwatch
    
    # Fail2ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 3
banaction = nftables-multiport
banaction_allports = nftables-allports
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 2

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

[http-auth]
enabled = true
filter = apache-auth
findtime = 300
maxretry = 3
EOF

    systemctl enable prometheus node_exporter fail2ban
    systemctl restart prometheus node_exporter fail2ban
}

# Funkcja konfigurująca automatyczne aktualizacje
setup_auto_updates() {
    log "INFO" "Konfiguracja automatycznych aktualizacji..."
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "${ADMIN_EMAIL}";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    # Konfiguracja apt-listchanges
    cat > /etc/apt/listchanges.conf << EOF
[apt]
frontend=mail
email_address=${ADMIN_EMAIL}
confirm=0
save_seen=/#!/bin/bash

# Strict mode
set -euo pipefail
IFS=$'\n\t'

# Script version
readonly SCRIPT_VERSION="2.0.0"

# Definicje
readonly GHOST_DIR="/var/www/ghost"
readonly SECURE_KEY_DIR="/etc/ghost/secure"
readonly LOG_DIR="/var/log/ghost"
readonly BACKUP_DIR="/var/backups/ghost"
readonly TEMP_DIR="/tmp/ghost_install_$$"
readonly LOCK_DIR="/var/run/ghost"
readonly REQUIRED_VARS=("DOMAIN" "ADMIN_EMAIL")
readonly PROMETHEUS_VERSION="2.45.0"
readonly NODE_EXPORTER_VERSION="1.6.1"

# Zmienne dla kolorowego outputu
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Funkcja czyszczenia
cleanup() {
    log "Czyszczenie zmiennych i plików tymczasowych..."
    # Czyszczenie wrażliwych zmiennych
    unset ENCRYPTION_KEY DB_PASS VAULT_TOKEN
    # Usuwanie plików tymczasowych
    rm -rf "${TEMP_DIR}"
    # Usuwanie locka
    rm -rf "${LOCK_DIR}/ghost_install.lock"
    # Czyszczenie pozostałych wrażliwych danych z pamięci
    if command -v dmsetup &> /dev/null; then
        echo 3 > /proc/sys/vm/drop_caches
    fi
}
trap cleanup EXIT
trap 'exit 1' SIGINT SIGTERM

# Włączanie trybu verbose jeśli ustawiono
[[ "${VERBOSE:-0}" == "1" ]] && set -x

# Funkcje logowania
setup_logging() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    readonly LOG_FILE="${LOG_DIR}/install_${timestamp}.log"
    readonly ERROR_LOG="${LOG_DIR}/error_${timestamp}.log"
    readonly AUDIT_LOG="${LOG_DIR}/audit_${timestamp}.log"
    
    # Tworzenie katalogów z odpowiednimi uprawnieniami
    install -d -m 750 "${LOG_DIR}"
    install -d -m 750 "${LOG_DIR}/archive"
    
    # Konfiguracja logrotate
    cat > /etc/logrotate.d/ghost << EOF
${LOG_DIR}/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 ghost ghost
    sharedscripts
    postrotate
        systemctl reload ghost
    endscript
}
EOF
    
    # Przekierowanie wyjścia
    exec 1> >(tee -a "${LOG_FILE}")
    exec 2> >(tee -a "${ERROR_LOG}" >&2)
    
    # Konfiguracja audytowania
    auditctl -w "${GHOST_DIR}" -p wa -k ghost_files
    auditctl -w "${SECURE_KEY_DIR}" -p wa -k ghost_secure
    
    log "Rozpoczęcie instalacji Ghost v${SCRIPT_VERSION}"
}

log() {
    local level="INFO"
    if [[ $# -gt 1 ]]; then
        level="$1"
        shift
    fi
    
    local color="$NC"
    case "$level" in
        "ERROR") color="$RED" ;;
        "WARN")  color="$YELLOW" ;;
        "INFO")  color="$GREEN" ;;
    esac
    
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] $*${NC}" | tee -a "${AUDIT_LOG}"
}

error_log() {
    log "ERROR" "$*"
    exit 1
}

# System blokad
acquire_lock() {
    local lock_name="$1"
    local lock_file="${LOCK_DIR}/${lock_name}.lock"
    
    mkdir -p "${LOCK_DIR}"
    if ! mkdir "${lock_file}" 2>/dev/null; then
        if [[ -f "${lock_file}/pid" ]]; then
            local pid
            pid=$(<"${lock_file}/pid")
            if kill -0 "$pid" 2>/dev/null; then
                error_log "Proces $lock_name już działa (PID: $pid)"
            else
                log "WARN" "Znaleziono osierocony lock, usuwanie..."
                rm -rf "${lock_file}"
                mkdir "${lock_file}"
            fi
        fi
    fi
    echo $$ > "${lock_file}/pid"
}

release_lock() {
    local lock_name="$1"
    rm -rf "${LOCK_DIR}/${lock_name}.lock"
}

# Walidacja zmiennych środowiskowych
validate_environment() {
    log "INFO" "Sprawdzanie zmiennych środowiskowych..."
    
    for var in "${REQUIRED_VARS[@]}"; do
        if [[ -z "${!var-}" ]]; then
            error_log "Brak wymaganej zmiennej środowiskowej: $var"
        fi
    done
    
    # Walidacja formatu zmiennych
    if ! echo "${ADMIN_EMAIL}" | grep -qE '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'; then
        error_log "Nieprawidłowy format adresu email: ${ADMIN_EMAIL}"
    fi
    
    if ! echo "${DOMAIN}" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'; then
        error_log "Nieprawidłowy format domeny: ${DOMAIN}"
    fi
}

# Funkcja sprawdzająca wymagania systemowe
check_system_requirements() {
    log "INFO" "Sprawdzanie wymagań systemowych..."
    
    # Sprawdzenie czy skrypt jest uruchomiony jako root
    if [[ $EUID -ne 0 ]]; then
        error_log "Ten skrypt musi być uruchomiony jako root"
    fi
    
    # Sprawdzenie systemu operacyjnego
    if [[ ! -f /etc/os-release ]]; then
        error_log "Nie można określić wersji systemu operacyjnego"
    fi
    
    source /etc/os-release
    if [[ "${ID}" != "ubuntu" && "${ID}" != "debian" ]]; then
        error_log "Niewspierany system operacyjny: ${ID}"
    fi
    
    # Sprawdzenie minimalnych wymagań sprzętowych
    local min_ram=1024000  # 1GB w KB
    local available_ram
    available_ram=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    if ((available_ram < min_ram)); then
        error_log "Za mało pamięci RAM. Minimum 1GB wymagane."
    fi
    
    # Sprawdzenie miejsca na dysku z uwzględnieniem potrzeb
    local required_space
    if [[ -d "${GHOST_DIR}" ]]; then
        required_space=$(du -s "${GHOST_DIR}" | awk '{print $1 * 3}')  # 3x obecna wielkość
    else
        required_space=5242880  # 5GB w KB
    fi
    
    local available_space
    available_space=$(df / | awk 'NR==2 {print $4}')
    if ((available_space < required_space)); then
        error_log "Za mało miejsca na dysku. Wymagane: ${required_space}KB, dostępne: ${available_space}KB"
    fi
    
    # Sprawdzenie wymaganych portów
    local required_ports=(80 443 2368 9100 9090)
    for port in "${required_ports[@]}"; do
        if netstat -tuln | grep -q ":${port} "; then
            error_log "Port ${port} jest już zajęty"
        fi
    done
    
    # Sprawdzenie dostępu do internetu
    if ! curl -s --connect-timeout 5 https://api.github.com >/dev/null; then
        error_log "Brak dostępu do internetu"
    fi
}

# Funkcja instalująca wymagane pakiety
install_required_packages() {
    log "INFO" "Instalacja wymaganych pakietów..."
    
    # Aktualizacja list pakietów z timeoutem
    local timeout=300
    if ! timeout "$timeout" apt-get update; then
        error_log "Nie można zaktualizować listy pakietów w ciągu ${timeout}s"
    fi
    
    local packages=(
        curl unzip nginx-extras tar ufw certbot
        python3-certbot-nginx fail2ban mariadb-server
        redis-server iptables git build-essential
        libpcre3 libpcre3-dev zlib1g-dev openssl
        libssl-dev htop glances lynis cmake golang
        libunwind-dev libatomic1 ninja-build expect
        aide logwatch acl vault prometheus
        auditd apparmor-utils needrestart
        unattended-upgrades apt-listchanges
        rkhunter chkrootkit clamav
        net-tools iproute2 tcpdump
    )
    
    # Instalacja pakietów z progress barem
    local total=${#packages[@]}
    local current=0
    
    for package in "${packages[@]}"; do
        current=$((current + 1))
        local progress=$((current * 100 / total))
        log "INFO" "[$progress%] Instalacja $package..."
        
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"; then
            error_log "Nie można zainstalować pakietu: $package"
        fi
    done
    
    # Aktualizacja definicji ClamAV
    freshclam
}

# Konfiguracja AppArmor
setup_apparmor() {
    log "INFO" "Konfiguracja AppArmor..."
    
    cat > /etc/apparmor.d/usr.sbin.ghost << EOF
#include <tunables/global>

profile ghost /usr/sbin/ghost {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/openssl>
    #include <abstractions/ssl_certs>
    
    # Ghost directory
    ${GHOST_DIR}/ r,
    ${GHOST_DIR}/** rwk,
    
    # Config access
    /etc/ghost/** r,
    
    # Logs
    ${LOG_DIR}/ r,
    ${LOG_DIR}/** w,
    
    # System access
    /proc/sys/net/core/somaxconn r,
    /sys/kernel/mm/transparent_hugepage/enabled r,
    
    # Node.js
    /usr/bin/node ix,
    /usr/lib/node_modules/** mr,
    
    # Deny everything else
    deny /** w,
}
EOF

    apparmor_parser -r /etc/apparmor.d/usr.sbin.ghost
}

# Funkcja konfigurująca bezpieczny system plików
setup_secure_filesystem() {
    log "INFO" "Konfiguracja bezpiecznego systemu plików..."
    
    # Tworzenie bezpiecznych katalogów
    local directories=(
        "$GHOST_DIR"
        "$SECURE_KEY_DIR"
        "$BACKUP_DIR"
        "$TEMP_DIR"
        "$LOG_DIR"
        "${GHOST_DIR}/content/data"
        "${GHOST_DIR}/content/images"
        "${GHOST_DIR}/content/themes"
    )
    
    for dir in "${directories[@]}"; do
        if ! install -d -m 0750 "$dir"; then
            error_log "Nie można utworzyć katalogu: $dir"
        fi
    done
    
    # Ustawienie dodatkowych zabezpieczeń dla katalogów
    chmod 1750 "$SECURE_KEY_DIR"  # sticky bit
    
    # Konfiguracja ACL
    local acl_dirs=(
        "$GHOST_DIR"
        "${GHOST_DIR}/content"
        "${GHOST_DIR}/content/data"
        "${GHOST_DIR}/content/images"
    )
    
    for dir in "${acl_dirs[@]}"; do
        setfacl -R -m u:ghost:rwx,g:ghost:rx "$dir"
        setfacl -R -d -m u:ghost:rwx,g:ghost:rx "$dir"
    done
    
    # Zabezpieczenie systemu plików
    local mount_opts="noexec,nosuid,nodev"
    
    # Montowanie /tmp z dodatkowymi opcjami
    if ! grep -q '/tmp' /etc/fstab; then
        echo "tmpfs /tmp tmpfs ${mount_opts},size=2G 0 0" >> /etc/fstab
        mount -o remount /tmp
    fi
    
    # Konfiguracja uprawnień dla wrażliwych plików
    find "$SECURE_KEY_DIR" -type f -exec chmod 600 {} \;
    find "$SECURE_KEY_DIR" -type d -exec chmod 700 {} \;
    
    # Ustawienie atrybutów immutable dla krytycznych plików
    local immutable_files=(
        "/etc/ghost/config.production.json"
        "${SECURE_KEY_DIR}/ghost.key"
    )
    
    for file in "${immutable_files[@]}"; do
        if [[ -f "$file" ]]; then
            chattr +i "$file"
        fi
    done
}

# Konfiguracja Vault
setup_vault() {
    log "INFO" "Konfiguracja Vault..."
    
    # Generowanie konfiguracji Vault
    cat > /etc/vault.d/config.hcl << EOF
storage "file" {
    path = "/opt/vault/data"
}

listener "tcp" {
    address = "127.0.0.1:8200"
    tls_disable = 1
}

api_addr = "http://127.0.0.1:8200"
disable_mlock = true

telemetry {
    prometheus_retention_time = "30s"
    disable_hostname = true
}
EOF

    # Tworzenie katalogu dla danych Vault
    install -d -m 0700 /opt/vault/data
    chown vault:vault /opt/vault/data

    # Uruchomienie Vault
    systemctl enable vault
    systemctl start vault
    
    # Inicjalizacja Vault
    local vault_init
    vault_init=$(vault operator init -key-shares=5 -key-threshold=3 -format=json)
    
    # Zapisanie kluczy do zaszyfrowanego pliku
    local vault_keys_file="${SECURE_KEY_DIR}/vault-keys.enc"
    echo "$vault_init" | openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in - -out "$vault_keys_file" -k "${ADMIN_EMAIL}"
    chmod 600 "$vault_keys_file"
    
    # Automatyczne odpieczętowanie Vault
    local unseal_keys
    unseal_keys=$(echo "$vault_init" | jq -r '.unseal_keys_b64[]' | head -n 3)
    while read -r key; do
        vault operator unseal "$key"
    done <<< "$unseal_keys"
    
    # Logowanie do Vault
    export VAULT_TOKEN=$(echo "$vault_init" | jq -r '.root_token')
    
    # Konfiguracja polityk Vault
    cat > /etc/vault.d/ghost-policy.hcl << EOF
path "secret/ghost/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
    
    vault policy write ghost-policy /etc/vault.d/ghost-policy.hcl
}

# Funkcja generująca bezpieczne poświadczenia
generate_secure_credentials() {
    log "INFO" "Generowanie bezpiecznych poświadczeń..."
    
    # Generowanie losowych wartości z wysoką entropią
    local db_name
    local db_user
    local db_pass
    local admin_pass
    local encryption_key
    
    db_name=$(tr -dc 'a-z0-9' < /dev/urandom | fold -w 16 | head -n 1)
    db_user=$(tr -dc 'a-z0-9' < /dev/urandom | fold -w 16 | head -n 1)
    db_pass=$(openssl rand -base64 48)
    admin_pass=$(openssl rand -base64 48)
    encryption_key=$(openssl rand -base64 32)
    
    # Zapisywanie poświadczeń do Vault z wersjonowaniem
    vault kv enable-versioning secret/ghost
    
    vault kv put secret/ghost/db \
        name="$db_name" \
        user="$db_user" \
        pass="$db_pass"
    
    vault kv put secret/ghost/admin \
        email="${ADMIN_EMAIL}" \
        password="$admin_pass"
        
    vault kv put secret/ghost/encryption \
        key="$encryption_key"
        
    # Tworzenie polityki rotacji kluczy
    vault write sys/policies/password/ghost-rotation \
        policy="length=48 rule='charset: ascii-printable'"
}

# Funkcja rotacji kluczy
rotate_encryption_keys() {
    log "INFO" "Rotacja kluczy szyfrowania..."
    acquire_lock "key-rotation"
    
    local new_key
    new_key=$(openssl rand -base64 32)
    local old_key
    old_key=$(vault kv get -format=json secret/ghost/encryption | jq -r '.data.data.key')
    
    # Re-szyfrowanie backupów
    local temp_dir
    temp_dir=$(mktemp -d)
    
    find "$BACKUP_DIR" -name "*.enc" | while read -r file; do
        local temp_file="${temp_dir}/$(basename "$file")"
        
        # Deszyfrowanie starym kluczem
        if ! openssl enc -d -aes-256-cbc -salt -pbkdf2 \
            -pass env:old_key -in "$file" -out "$temp_file"; then
            log "WARN" "Nie można odszyfrować pliku: $file"
            continue
        fi
        
        # Szyfrowanie nowym kluczem
        if openssl enc -aes-256-cbc -salt -pbkdf2 \
            -pass env:new_key -in "$temp_file" -out "${file}.new"; then
            mv "${file}.new" "$file"
        else
            log "ERROR" "Błąd podczas szyfrowania pliku: $file"
            rm -f "${file}.new"
        fi
    done
    
    rm -rf "$temp_dir"
    
    # Aktualizacja klucza w Vault
    vault kv put secret/ghost/encryption key="$new_key"
    
    release_lock "key-rotation"
}

# Funkcja konfigurująca MariaDB
setup_mariadb() {
    log "INFO" "Konfiguracja MariaDB..."
    
    # Pobieranie poświadczeń z Vault
    local db_creds
    db_creds=$(vault kv get -format=json secret/ghost/db)
    local db_name
    local db_user
    local db_pass
    
    db_name=$(echo "$db_creds" | jq -r '.data.data.name')
    db_user=$(echo "$db_creds" | jq -r '.data.data.user')
    db_pass=$(echo "$db_creds" | jq -r '.data.data.pass')
    
    # Konfiguracja zabezpieczeń MariaDB
    cat > /etc/mysql/conf.d/security.cnf << EOF
[mysqld]
# Podstawowe zabezpieczenia
local-infile=0
skip-show-database
sql-mode=STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,NO_AUTO_CREATE_USER
symbolic-links=0
max_allowed_packet=16M
bind-address=127.0.0.1

# SSL/TLS
ssl=ON
ssl-cert=/etc/mysql/server-cert.pem
ssl-key=/etc/mysql/server-key.pem
ssl-cipher=TLS_AES_256_GCM_SHA384

# Bezpieczeństwo haseł
plugin-load-add=simple_password_check.so
simple_password_check_minimal_length=12
validate_password_policy=STRONG
validate_password_length=12

# Logowanie
log_error=/var/log/mysql/error.log
log_error_verbosity=3
slow_query_log=1
slow_query_log_file=/var/log/mysql/slow.log
long_query_time=2

# Dodatkowe zabezpieczenia
secure_file_priv=/var/lib/mysql-files
explicit_defaults_for_timestamp=1
EOF

    # Generowanie certyfikatów SSL dla MariaDB
    local mysql_ssl_dir="/etc/mysql/ssl"
    mkdir -p "$mysql_ssl_dir"
    
    openssl req -new -x509 -nodes -days 365 \
        -subj "/CN=ghost-mysql/O=Ghost/C=PL" \
        -keyout "${mysql_ssl_dir}/server-key.pem" \
        -out "${mysql_ssl_dir}/server-cert.pem"
        
    chmod 600 "${mysql_ssl_dir}/server-key.pem"
    chmod 644 "${mysql_ssl_dir}/server-cert.pem"
    
    # Tworzenie bazy i użytkownika
    mysql -e "CREATE DATABASE IF NOT EXISTS ${db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -e "CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';"
    mysql -e "GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'localhost' REQUIRE SSL;"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Konfiguracja backupów MariaDB
    cat > /etc/cron.daily/mariadb-backup << EOF
#!/bin/bash
set -euo pipefail

backup_dir="${BACKUP_DIR}/mysql"
date=\$(date +%Y%m%d_%H%M%S)
mkdir -p "\$backup_dir"

# Backup z kompresją
mariabackup --backup \\
    --target-dir="\$backup_dir/full_\${date}" \\
    --user=root \\
    --compress \\
    --compress-threads=4

# Czyszczenie starych backupów
find "\$backup_dir" -type d -name "full_*" -mtime +7 -exec rm -rf {} +
EOF
    chmod 700 /etc/cron.daily/mariadb-backup
    
    systemctl restart mariadb
}

# Funkcja konfigurująca Nginx z HTTP/3
setup_nginx() {
    log "INFO" "Konfiguracja Nginx..."
    
    # Generowanie silnych parametrów DH
    if ! [[ -f /etc/nginx/dhparam.pem ]]; then
        openssl dhparam -out /etc/nginx/dhparam.pem 4096 || {
            error_log "Nie można wygenerować parametrów DH"
        }
    fi
    
    # Konfiguracja HTTP/3
    cat > /etc/nginx/conf.d/http3.conf << EOF
# Optymalizacja wydajności
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    multi_accept on;
    worker_connections 65535;
}

# Konfiguracja HTTP
http {
    # Podstawowe ustawienia
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # Limity i bufory
    client_max_body_size 10M;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    
    # Buforowanie open_file
    open_file_cache max=1000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=ghost_api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=ghost_admin:10m rate=5r/s;
    
    # SSL
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # Współczesne konfiguracje SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 1.0.0.1 [2606:4700:4700::1111] [2606:4700:4700::1001] valid=300s;
    resolver_timeout 5s;
    
    # Konfiguracja HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        listen 443 quic reuseport;
        listen [::]:443 quic reuseport;
        
        server_name ${DOMAIN};
        
        # SSL
        ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
        ssl_trusted_certificate /etc/letsencrypt/live/${DOMAIN}/chain.pem;
        
        # HTTP/3
        add_header Alt-Svc 'h3=":443"; ma=86400' always;
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self';" always;
        add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
        
        # Cookie security
        proxy_cookie_path / "/; HttpOnly; Secure; SameSite=strict";
        
        # MIME type sniffing
        add_header X-Content-Type-Options "nosniff" always;
        
        # Compression
        brotli on;
        brotli_comp_level 6;
        brotli_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
        
        # Ghost API rate limiting
        location /ghost/api/ {
            limit_req zone=ghost_api burst=20 nodelay;
            proxy_pass http://127.0.0.1:2368;
        }
        
        # Ghost Admin rate limiting
        location /ghost/ {
            limit_req zone=ghost_admin burst=10 nodelay;
            proxy_pass http://127.0.0.1:2368;
        }
        
        # Static files
        location ~* \.(jpg|jpeg|gif|png|webp|ico|css|js|svg)$ {
            expires 7d;
            add_header Cache-Control "public, no-transform";
        }
        
        # Block access to sensitive files
        location ~ /\. {
            deny all;
        }
        
        location = /favicon.ico {
            log_not_found off;
            access_log off;
        }
        
        location = /robots.txt {
            allow all;
            log_not_found off;
            access_log off;
        }
        
        # Main proxy configuration
        location / {
            proxy_pass http://127.0.0.1:2368;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_set_header Host \$http_host;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
EOF
