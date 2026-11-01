#!/bin/bash
# tgweb 域名（tg domain 调用，也可直接用 tg-domain）：直接列出本机已有证书的域名，选一个就把域名和证书写进 Nginx 配置并重载；再运行就换域名。
# 证书目录：/root/cert/<域名>/ 或 /etc/nginx/cert/<域名>/，里面要有 fullchain.pem 和 privkey.pem。
# 生成的配置：/etc/nginx/conf.d/tgweb-domain.conf，只有一份，换域名就覆盖（反代本机 127.0.0.1:8000 的网页服务）。
# TGWEB-DOMAIN-TOOL（安装器靠这行识别 /usr/local/bin/tg-domain 是不是本工具）
set -uo pipefail
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "用法：tg domain [域名]"
  echo "  不给域名：列出本机已有证书，选一个绑定；选 1 取消域名，选 0 退出。"
  echo "  给域名：直接用该域名的证书绑定（没有就试泛域名、父域名证书）。"
  echo "  证书要自己先准备好，放在 /root/cert/<域名>/ 或 /etc/nginx/cert/<域名>/ 里。"
  exit 0
fi
[ "$(id -u)" = 0 ] || exec sudo bash "$0" "$@"

CONF=/etc/nginx/conf.d/tgweb-domain.conf
OLD_PREFIX=/etc/nginx/conf.d/tgweb-domain-   # 旧版每个域名一份，换成单份时清掉
APP_UPSTREAM=http://127.0.0.1:8000

re='\033[0m'; red='\033[1;91m'
red()     { echo -e "\033[1;91m$1\033[0m"; }
green()   { echo -e "\033[1;32m$1\033[0m"; }
yellow()  { echo -e "\033[1;93m$1\033[0m"; }
skyblue() { echo -e "\033[1;96m$1\033[0m"; }
reading() { read -r -p "$(echo -e "\033[1;91m$1\033[0m")" "$2" </dev/tty; }

# 检查并选择已有证书
# 调用：check_and_issue_ssl [域名] || return 1   结果在 domain / cert_file / key_file
check_and_issue_ssl() {
    local input_domain="$1"
    domain=""; cert_file=""; key_file=""

    # 无指定域名：显示本地已有证书列表
    if [[ -z "$input_domain" ]]; then
        local cert_domains=() cert_paths=() dir d_name
        shopt -s nullglob
        for dir in /root/cert/* /etc/nginx/cert/*; do
            if [[ -d "$dir" && -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
                d_name=$(basename "$dir")
                if [[ ! " ${cert_domains[*]} " =~ " ${d_name} " ]]; then
                    cert_domains+=("$d_name"); cert_paths+=("$dir")
                fi
            fi
        done
        shopt -u nullglob

        echo
        local cur_domain=""; [[ -f "$CONF" ]] && cur_domain=$(awk '$1=="server_name"{sub(/;$/,"",$2); print $2; exit}' "$CONF")
        skyblue "============== 选择使用的域名 =============="
        [[ -n "$cur_domain" ]] && echo -e " 当前域名：\033[1;32m${cur_domain}\033[0m"
        local i=2 idx
        if [[ ${#cert_domains[@]} -eq 0 ]]; then
            echo "  (未检测到任何本地证书)"
        else
            for idx in "${!cert_domains[@]}"; do
                local cert_mark="" cert_file_tmp="${cert_paths[$idx]}/fullchain.pem"
                if openssl x509 -in "$cert_file_tmp" -noout -issuer 2>/dev/null | grep -qi "CloudFlare Origin SSL"; then
                    cert_mark=" ${red}【15年证书】${re}"
                fi
                [[ "${cert_domains[$idx]}" == "$cur_domain" ]] && cert_mark+=" \033[1;32m【当前】\033[0m"
                echo -e " ${i}) ${cert_domains[$idx]}${cert_mark}  (路径: ${cert_paths[$idx]})"
                ((i++))
            done
        fi
        skyblue "=============================================="
        [[ -n "$cur_domain" ]] && echo " 1) 取消域名（删除域名配置）"
        echo " 0) 退出"
        echo

        local menu_choice
        reading "请选择已有证书序号 [2-$((i-1))] 或 0 退出: " menu_choice
        if [[ "$menu_choice" == "0" ]]; then red "已取消操作。"; return 1; fi
        if [[ "$menu_choice" == "1" && -n "$cur_domain" ]]; then domain=""; return 2; fi
        if [[ "$menu_choice" =~ ^[0-9]+$ ]] && [[ "$menu_choice" -ge 2 ]] && [[ "$menu_choice" -lt "$i" ]]; then
            local sel_idx=$((menu_choice - 2))
            domain="${cert_domains[$sel_idx]}"
            cert_file="${cert_paths[$sel_idx]}/fullchain.pem"
            key_file="${cert_paths[$sel_idx]}/privkey.pem"
            green "已选择并使用域名 ${domain} 的现有证书。"
            return 0
        fi
        red "无效的选择！"; return 1
    fi

    # 指定域名
    domain=$(echo "$input_domain" | tr -d '[:space:]')
    if [[ -z "$domain" ]]; then red "域名不能为空！"; return 1; fi

    # 1. 该域名自己的证书
    local existing_path=""
    if [[ -f "/root/cert/${domain}/fullchain.pem" && -f "/root/cert/${domain}/privkey.pem" ]]; then
        existing_path="/root/cert/${domain}"
    elif [[ -f "/etc/nginx/cert/${domain}/fullchain.pem" && -f "/etc/nginx/cert/${domain}/privkey.pem" ]]; then
        existing_path="/etc/nginx/cert/${domain}"
    fi
    if [[ -n "$existing_path" ]]; then
        cert_file="${existing_path}/fullchain.pem"; key_file="${existing_path}/privkey.pem"
        skyblue "检测到域名 ${domain} 的证书已存在，直接使用。"
        return 0
    fi

    # 2. 泛域名证书（api.example.com → *.example.com）
    if [[ "$domain" == *.*.* ]]; then
        local parent_domain="${domain#*.}" wildcard_cert="" wildcard_key="" wdir
        for wdir in "/root/cert/*.${parent_domain}" "/etc/nginx/cert/*.${parent_domain}"; do
            if [[ -f "$wdir/fullchain.pem" && -f "$wdir/privkey.pem" ]]; then
                wildcard_cert="$wdir/fullchain.pem"; wildcard_key="$wdir/privkey.pem"; break
            fi
        done
        if [[ -n "$wildcard_cert" ]]; then
            yellow "检测到可用泛域名证书 (*.${parent_domain})。"
            local use_wildcard
            reading "是否直接使用该泛域名证书保护 ${domain}？(y/n): " use_wildcard
            if [[ "$use_wildcard" == "y" || "$use_wildcard" == "Y" ]]; then
                cert_file="$wildcard_cert"; key_file="$wildcard_key"
                green "已选择使用泛域名证书。"; return 0
            fi
        fi

        # 3. 父域名普通证书
        local parent_cert="" parent_key=""
        if [[ -f "/root/cert/${parent_domain}/fullchain.pem" && -f "/root/cert/${parent_domain}/privkey.pem" ]]; then
            parent_cert="/root/cert/${parent_domain}/fullchain.pem"; parent_key="/root/cert/${parent_domain}/privkey.pem"
        elif [[ -f "/etc/nginx/cert/${parent_domain}/fullchain.pem" && -f "/etc/nginx/cert/${parent_domain}/privkey.pem" ]]; then
            parent_cert="/etc/nginx/cert/${parent_domain}/fullchain.pem"; parent_key="/etc/nginx/cert/${parent_domain}/privkey.pem"
        fi
        if [[ -n "$parent_cert" ]]; then
            yellow "当前域名无证书，但检测到父域名 ${parent_domain} 已有普通证书。"
            local use_parent
            reading "是否尝试使用父域名证书？(y/n): " use_parent
            if [[ "$use_parent" == "y" || "$use_parent" == "Y" ]]; then
                cert_file="$parent_cert"; key_file="$parent_key"
                green "已选择使用 ${parent_domain} 的证书。"; return 0
            fi
        fi
    fi

    red "未找到域名 ${domain} 的可用证书。"
    red "证书申请功能已移除，请手动准备证书后重试。"
    return 1
}

reload_or_rollback() {   # $1 = 备份文件（空 = 原来没有配置）
    local out
    if out=$(nginx -t 2>&1); then systemctl reload nginx; rm -f "$1"; return 0; fi
    if [[ -n "$1" ]]; then mv "$1" "$CONF"; else rm -f "$CONF"; fi
    red "Nginx 配置检查没通过，已恢复原来的配置："
    echo "$out" | sed 's/^/  /'
    return 1
}

check_and_issue_ssl "${1:-}"; rc=$?
[[ $rc == 1 ]] && exit 1

backup=""
[[ -f "$CONF" ]] && { backup=$(mktemp); cp "$CONF" "$backup"; }

if [[ $rc == 2 ]]; then
    rm -f "$CONF"
    reload_or_rollback "$backup" && green "已取消域名（证书文件没动）。"
    exit
fi

# 别的 Nginx 配置已经用了这个域名：提醒（同一域名两个 server 块，Nginx 只认第一个）
pat="${domain//./\\.}"; pat="${pat//\*/\\*}"
other=$(grep -rlsE "server_name[^;]*[[:space:]]${pat}([[:space:];]|$)" /etc/nginx/ 2>/dev/null | grep -v "^${CONF}$" | grep -v "^${OLD_PREFIX}" || true)
if [[ -n "$other" ]]; then
    yellow "注意：下面的 Nginx 配置也在用 ${domain}，可能冲突（只有一个生效）："
    echo "$other" | sed 's/^/  /'
fi

cat > "$CONF" <<EOF
# tgweb 域名（由 tg domain 生成；再运行 tg domain 可换域名）
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${domain};
    server_tokens off;
    ssl_certificate     ${cert_file};
    ssl_certificate_key ${key_file};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    location / {
        proxy_pass ${APP_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 0;
    }
}
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    return 301 https://\$host\$request_uri;
}
EOF
olds=( ${OLD_PREFIX}*.conf ); old_bak=$(mktemp -d)
for f in "${olds[@]}"; do [[ -f "$f" ]] && mv "$f" "$old_bak/"; done
if reload_or_rollback "$backup"; then
    rm -rf "$old_bak"
    green "域名已设置：https://${domain}"
    echo "  证书：${cert_file}"
    echo "  私钥：${key_file}"
else
    mv "$old_bak"/* /etc/nginx/conf.d/ 2>/dev/null; rm -rf "$old_bak"
    exit 1
fi
