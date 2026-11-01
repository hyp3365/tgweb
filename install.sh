#!/bin/bash
set -e
# 一键安装：Debian / Ubuntu，root 运行
# 用法：bash <(curl -fsSL https://raw.githubusercontent.com/hyp3365/tgweb/main/install.sh)
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  echo "用法：bash <(curl -fsSL https://raw.githubusercontent.com/hyp3365/tgweb/main/install.sh)"
  echo "安装目录：\${TGWEB_DIR:-/root/telegram-stream}，已有 .env 不会被覆盖，改配置用 tg 命令。"
  exit 0
fi
REPO="https://github.com/hyp3365/tgweb.git"
DIR="${TGWEB_DIR:-/root/telegram-stream}"
if [ "$(id -u)" != "0" ]; then
  echo "请用 root 运行。"
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "只支持 Debian / Ubuntu（需要 apt）。"
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git curl ca-certificates openssl
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || { echo "Docker Compose 未装好，请检查 Docker 安装。"; exit 1; }

# 取代码：已有目录且不是 git 仓库时先备份，再全新克隆，并把旧 .env 和 data 拷回来
if [ -d "$DIR/.git" ]; then
  (cd "$DIR" && git pull --ff-only || echo "git pull 失败，继续用现有代码。")
elif [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
  BACKUP="${DIR}.bak.$(date +%Y%m%d%H%M%S)"
  mv "$DIR" "$BACKUP"
  git clone "$REPO" "$DIR"
  [ -f "$BACKUP/.env" ] && cp "$BACKUP/.env" "$DIR/.env"
  [ -d "$BACKUP/data" ] && mkdir -p "$DIR/data" && cp -r "$BACKUP/data/." "$DIR/data/" 2>/dev/null || true
  echo "旧目录已备份到 $BACKUP"
else
  git clone "$REPO" "$DIR"
fi

# 装 tg 快捷命令和域名工具
cp "$DIR/tg" /usr/local/bin/tg
chmod +x /usr/local/bin/tg
cp "$DIR/tg-domain.sh" /usr/local/bin/tg-domain
chmod +x /usr/local/bin/tg-domain
# tg 默认目录就是 /root/telegram-stream；装到别的目录时用 TG_APP_DIR 指向它
if [ "$DIR" != "/root/telegram-stream" ]; then
  echo "注意：tg 默认目录是 /root/telegram-stream，你装在 $DIR，请用 TG_APP_DIR=$DIR tg"
fi

# .env：已有就不动，没有就新建
NEW_PW=""
if [ ! -f "$DIR/.env" ]; then
  API_ID="${TG_API_ID:-}"
  API_HASH="${TG_API_HASH:-}"
  WEB_PW="${WEB_PASSWORD:-}"
  if [ -t 0 ] && [ -z "$API_ID" ]; then
    read -r -p "api_id（纯数字，回车跳过，装完再用 tg set-id 补）： " API_ID || true
  fi
  if [ -t 0 ] && [ -z "$API_HASH" ]; then
    read -r -s -p "api_hash（输入不显示，回车跳过，装完再用 tg set-hash 补）： " API_HASH || true
    echo ""
  fi
  if [ -t 0 ] && [ -z "$WEB_PW" ]; then
    read -r -s -p "网页密码（输入不显示，回车自动生成一个）： " WEB_PW || true
    echo ""
  fi
  if [ -z "$API_ID" ]; then API_ID="0"; fi
  if [ -z "$API_HASH" ]; then API_HASH="placeholder"; fi
  if [ -z "$WEB_PW" ]; then
    WEB_PW="$(openssl rand -hex 8)"
    NEW_PW="$WEB_PW"
  elif python3 -c 'import sys; pw=sys.argv[1]; bad=[chr(36),chr(35),chr(39),chr(34),chr(92)]; sys.exit(0 if any(c in pw for c in bad) or any(c.isspace() for c in pw) else 1)' "$WEB_PW"; then
    echo "提供的网页密码含美元符、井号、引号、空格或反斜杠，.env 会被 docker compose 认错，已改成自动生成的安全密码。"
    WEB_PW="$(openssl rand -hex 8)"
    NEW_PW="$WEB_PW"
  fi
  printf 'TG_API_ID=%s\nTG_API_HASH=%s\nWEB_PASSWORD=%s\n' "$API_ID" "$API_HASH" "$WEB_PW" > "$DIR/.env"
  chmod 600 "$DIR/.env"
else
  echo "已有 .env，保留不动，改配置用 tg 命令。"
fi

(cd "$DIR" && docker compose up -d --build)
sleep 5
docker compose -f "$DIR/docker-compose.yml" ps
if curl -fsS http://127.0.0.1:8000/ >/dev/null 2>&1; then
  echo "服务已启动。"
else
  echo "服务启动检查失败，请在 $DIR 里看 docker compose logs。"
fi
# 8000 只绑回环，不直接对公网开放；80 口走 nginx 反代，tg domain 绑域名后 HTTPS 才不会被 8000 直连绕过
NGINX_OK=0
if grep -rq "proxy_pass http://127.0.0.1:8000" /etc/nginx/ 2>/dev/null; then
  echo "检测到已有 Nginx 反代到 8000，跳过 Nginx 配置。"
  NGINX_OK=1
else
  if ! command -v nginx >/dev/null 2>&1; then
    apt-get install -y nginx 2>/dev/null || true
  fi
  if command -v nginx >/dev/null 2>&1; then
    cat > /etc/nginx/conf.d/tgweb.conf <<'NGINXEOF'
server {
    listen 80;
    server_name _;
    server_tokens off;
    client_max_body_size 0;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
NGINXEOF
    if nginx -t 2>/dev/null; then
      systemctl reload nginx 2>/dev/null || systemctl start nginx 2>/dev/null || true
      NGINX_OK=1
    else
      rm -f /etc/nginx/conf.d/tgweb.conf
      echo "Nginx 配置检查失败，已跳过反代，服务只能从本机 127.0.0.1:8000 访问。"
    fi
  fi
fi
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$IP" ] && IP="服务器IP"
echo ""
if [ "$NGINX_OK" = "1" ]; then
  echo "访问地址：http://$IP/"
else
  echo "访问地址：http://127.0.0.1:8000（仅本机，请自行配反代）"
fi
if [ -n "$NEW_PW" ]; then
  echo "网页密码（刚生成的，请记下来）：$NEW_PW"
else
  echo "网页密码：已有 .env 的不变，用 tg show-password 在服务器终端查看。"
fi
echo "如需 HTTPS，用 tg domain 绑定域名。"
