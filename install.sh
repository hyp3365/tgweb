#!/bin/bash
set -e
# 一键安装：Debian / Ubuntu，root 运行
# 用法：bash <(curl -fsSL https://raw.githubusercontent.com/hyp3365/tgweb/main/install.sh)
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  echo "用法：bash <(curl -fsSL https://raw.githubusercontent.com/hyp3365/tgweb/main/install.sh)"
  echo "安装目录：\${TGWEB_DIR:-/root/telegram-stream}，已有 .env 不会被覆盖，改配置用 tg 命令。"
  echo "安装后必须绑定域名或有证书的 IP，不提供 HTTP 访问；证书要先放在 /root/cert/<域名或IP>/ 里，或用 TGWEB_DOMAIN 环境变量指定要绑的域名/IP。"
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
  # pull 失败就停下来，不要悄悄用旧代码继续构建：本地改动、分支分叉、网络中断
  # 时继续装，装完显示“已启动”会让用户误以为已经是最新版。
  if ! (cd "$DIR" && git pull --ff-only); then
    echo "git pull 失败，已停止安装，没有用旧代码继续构建。"
    echo "请先在 $DIR 里处理本地改动或分支分叉（git status / git stash），再重新运行安装。"
    exit 1
  fi
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
  WEB_PATH="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 24)"
  if [ "${#WEB_PATH}" != "24" ]; then WEB_PATH="$(openssl rand -hex 12)"; fi
  printf 'TG_API_ID=%s\nTG_API_HASH=%s\nWEB_PASSWORD=%s\nWEB_PATH=%s\n' "$API_ID" "$API_HASH" "$WEB_PW" "$WEB_PATH" > "$DIR/.env"
  chmod 600 "$DIR/.env"
else
  echo "已有 .env，保留不动，改配置用 tg 命令。"
  if ! grep -q "^WEB_PATH=" "$DIR/.env" 2>/dev/null; then
    _NP="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 24)"
    if [ "${#_NP}" = "24" ]; then
      printf 'WEB_PATH=%s\n' "$_NP" >> "$DIR/.env"
      echo "已有 .env 里没有访问路径，已自动生成一个24位路径，完整地址见绑定后的提示，或用 tg show-path 查看。"
    fi
  fi
fi

(cd "$DIR" && docker compose up -d --build)
sleep 5
docker compose -f "$DIR/docker-compose.yml" ps
# 健康检查必须带 WEB_PATH：app 的中间件对不带访问路径的 / 直接回 404，
# 以前这里裸 curl /，新装（一定会生成 WEB_PATH）永远报“启动检查失败”，其实服务是好的。
_HEALTH_PATH="$(grep -E '^WEB_PATH=' "$DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
if [ -n "$_HEALTH_PATH" ]; then
  _HEALTH_URL="http://127.0.0.1:8000/$_HEALTH_PATH"
else
  _HEALTH_URL="http://127.0.0.1:8000/"
fi
if curl -fsS "$_HEALTH_URL" >/dev/null 2>&1; then
  echo "服务已启动。"
else
  echo "服务启动检查失败（检查的是 $_HEALTH_URL），请在 $DIR 里看 docker compose logs。"
fi
# 8000 只绑回环，不直接对公网开放；不提供 HTTP 访问：安装后必须绑定域名或有证书的 IP，走 HTTPS 才能进应用
# 旧的 HTTP 反代必须删掉，否则 HTTPS 会被 HTTP 明文绕过
rm -f /etc/nginx/conf.d/tgweb.conf
if ! command -v nginx >/dev/null 2>&1; then
  apt-get install -y nginx 2>/dev/null || true
fi
# 已有 HTTPS 站点（tg domain 绑过的域名，或原来 IP 的 HTTPS 站）就保留不动，不用重新绑
# 注意不能用两个跨文件的 grep 拼结果：一个文件有 443、另一个文件反代 8000，
# 拼起来也会误判成“已有 tgweb 的 HTTPS 站”，然后直接退出不绑定，实际上 tgweb 根本没对外。
_HAS_HTTPS=0
for _f in /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
  if [ -f "$_f" ] && grep -q "listen 443 ssl" "$_f" 2>/dev/null && grep -q "proxy_pass http://127.0.0.1:8000" "$_f" 2>/dev/null; then
    _HAS_HTTPS=1
    break
  fi
done
if [ "$_HAS_HTTPS" = "1" ]; then
  echo "检测到已有 HTTPS 站点，保留不动，继续用原来的 https 地址访问。"
  if [ -n "$NEW_PW" ]; then
    echo "网页密码（刚生成的，请记下来）：$NEW_PW"
  else
    echo "网页密码：已有 .env 的不变，用 tg show-password 在服务器终端查看。"
  fi
  exit 0
fi
if ! command -v nginx >/dev/null 2>&1; then
  echo "Nginx 未装好，无法建 HTTPS 站点。服务只在 127.0.0.1:8000 运行，不提供 HTTP 访问。"
  echo "装好 Nginx、准备好证书后，运行 tg domain <域名或IP> 绑定。"
  exit 1
fi
BIND_NAME="${TGWEB_DOMAIN:-}"
if [ -z "$BIND_NAME" ] && [ -t 0 ]; then
  read -r -p "要绑定的域名或 IP（证书要已在 /root/cert/<域名或IP>/ 里，留空则不绑定）： " BIND_NAME || true
fi
BIND_NAME="$(echo "$BIND_NAME" | tr -d '[:space:]')"
if [ -z "$BIND_NAME" ]; then
  echo ""
  echo "未绑定域名或 IP 证书，外部访问未开通：服务只在 127.0.0.1:8000 运行，不提供 HTTP 访问。"
  echo "请把证书放到 /root/cert/<域名或IP>/fullchain.pem 和 privkey.pem，然后运行 tg domain <域名或IP> 绑定，再用 https://<域名或IP>/<访问路径> 访问（路径用 tg show-path 查看）。"
  if [ -d /root/cert ] || [ -d /etc/nginx/cert ]; then
    echo "本机已有证书："
    for d in /root/cert/* /etc/nginx/cert/*; do
      if [ -f "$d/fullchain.pem" ] && [ -f "$d/privkey.pem" ]; then echo "  $(basename "$d")"; fi
    done 2>/dev/null || true
  fi
  if [ -n "$NEW_PW" ]; then
    echo "网页密码（刚生成的，请记下来）：$NEW_PW"
  else
    echo "网页密码：已有 .env 的不变，用 tg show-password 在服务器终端查看。"
  fi
  exit 1
fi
if [ -f "/root/cert/$BIND_NAME/fullchain.pem" ] && [ -f "/root/cert/$BIND_NAME/privkey.pem" ]; then
  :
elif [ -f "/etc/nginx/cert/$BIND_NAME/fullchain.pem" ] && [ -f "/etc/nginx/cert/$BIND_NAME/privkey.pem" ]; then
  :
else
  echo ""
  echo "域名/IP $BIND_NAME 的证书不存在：/root/cert/$BIND_NAME/ 或 /etc/nginx/cert/$BIND_NAME/ 里要有 fullchain.pem 和 privkey.pem。"
  echo "安装不会提供 HTTP 访问。请准备好证书后运行 tg domain $BIND_NAME 绑定（tg domain 还能用泛域名/父域名证书），再用 https://$BIND_NAME/<访问路径> 访问（路径用 tg show-path 查看）。"
  if [ -n "$NEW_PW" ]; then
    echo "网页密码（刚生成的，请记下来）：$NEW_PW"
  else
    echo "网页密码：已有 .env 的不变，用 tg show-password 在服务器终端查看。"
  fi
  exit 1
fi
if /usr/local/bin/tg-domain "$BIND_NAME"; then
  echo ""
  _WP="$(grep -E "^WEB_PATH=" "$DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2-)"
  if [ -n "$_WP" ]; then
    echo "访问地址：https://$BIND_NAME/$_WP"
  else
    echo "访问地址：https://$BIND_NAME"
  fi
  if [ -n "$NEW_PW" ]; then
    echo "网页密码（刚生成的，请记下来）：$NEW_PW"
  else
    echo "网页密码：已有 .env 的不变，用 tg show-password 在服务器终端查看。"
  fi
else
  echo "绑定 $BIND_NAME 失败，外部访问未开通，不提供 HTTP 访问。"
  exit 1
fi
