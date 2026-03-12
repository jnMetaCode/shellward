#!/bin/bash
# ClawGuard One-Click Installer / 一键安装脚本
# Usage: curl -fsSL https://raw.githubusercontent.com/jnMetaCode/clawguard/main/install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Detect language
is_zh() {
  local lang="${LANG:-}${LANGUAGE:-}${LC_ALL:-}"
  [[ "$lang" == *zh* ]]
}

if is_zh; then
  MSG_BANNER="🛡️  ClawGuard 安全插件 一键安装"
  MSG_CHECKING="正在检查环境..."
  MSG_NODE_MISSING="❌ 未找到 Node.js (需要 v18+)。请先安装: https://nodejs.org"
  MSG_NODE_OLD="❌ Node.js 版本过低 (当前: %s, 需要: v18+)。请升级: https://nodejs.org"
  MSG_NODE_OK="✅ Node.js %s"
  MSG_OC_MISSING="❌ 未找到 OpenClaw。请先安装: npm install -g openclaw"
  MSG_OC_OK="✅ OpenClaw %s"
  MSG_INSTALLING="正在安装 ClawGuard..."
  MSG_ALREADY="⚠️  ClawGuard 已安装，正在更新..."
  MSG_CLONE="正在下载 ClawGuard..."
  MSG_NPM="通过 npm 安装..."
  MSG_REGISTER="正在注册插件..."
  MSG_SUCCESS="🎉 安装成功！"
  MSG_VERIFY="验证安装..."
  MSG_USAGE="使用方法:"
  MSG_CMD1="  openclaw agent --local -m \"你好\"   # 启动安全防护的 Agent"
  MSG_CMD2="  /security                            # 查看安全状态"
  MSG_CMD3="  /audit                               # 查看审计日志"
  MSG_CMD4="  /harden                              # 安全扫描"
  MSG_DOCS="文档: https://github.com/jnMetaCode/clawguard"
  MSG_MODE_TITLE="选择安装方式:"
  MSG_MODE_1="  1) npm 安装 (推荐，自动更新)"
  MSG_MODE_2="  2) 源码安装 (离线可用)"
  MSG_MODE_PROMPT="请输入 [1/2] (默认 1): "
  MSG_DONE="安装完成！ClawGuard 将在下次启动 OpenClaw 时自动加载。"
  MSG_CONFIG="配置文件 (可选):"
else
  MSG_BANNER="🛡️  ClawGuard Security Plugin — One-Click Install"
  MSG_CHECKING="Checking environment..."
  MSG_NODE_MISSING="❌ Node.js not found (v18+ required). Install: https://nodejs.org"
  MSG_NODE_OLD="❌ Node.js too old (current: %s, need: v18+). Upgrade: https://nodejs.org"
  MSG_NODE_OK="✅ Node.js %s"
  MSG_OC_MISSING="❌ OpenClaw not found. Install: npm install -g openclaw"
  MSG_OC_OK="✅ OpenClaw %s"
  MSG_INSTALLING="Installing ClawGuard..."
  MSG_ALREADY="⚠️  ClawGuard already installed, updating..."
  MSG_CLONE="Downloading ClawGuard..."
  MSG_NPM="Installing via npm..."
  MSG_REGISTER="Registering plugin..."
  MSG_SUCCESS="🎉 Installation successful!"
  MSG_VERIFY="Verifying installation..."
  MSG_USAGE="Usage:"
  MSG_CMD1="  openclaw agent --local -m \"hello\"   # Start agent with security"
  MSG_CMD2="  /security                            # View security status"
  MSG_CMD3="  /audit                               # View audit log"
  MSG_CMD4="  /harden                              # Security scan"
  MSG_DOCS="Docs: https://github.com/jnMetaCode/clawguard"
  MSG_MODE_TITLE="Choose install method:"
  MSG_MODE_1="  1) npm install (recommended, auto-update)"
  MSG_MODE_2="  2) source install (works offline)"
  MSG_MODE_PROMPT="Enter [1/2] (default 1): "
  MSG_DONE="Done! ClawGuard will auto-load next time OpenClaw starts."
  MSG_CONFIG="Configuration (optional):"
fi

echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  $MSG_BANNER${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

# --- Step 1: Check environment ---
echo -e "${BLUE}$MSG_CHECKING${NC}"

# Check Node.js
if ! command -v node &>/dev/null; then
  echo -e "${RED}$MSG_NODE_MISSING${NC}"
  exit 1
fi

NODE_VER=$(node -v)
NODE_MAJOR=$(echo "$NODE_VER" | sed 's/v//' | cut -d. -f1)
if [ "$NODE_MAJOR" -lt 18 ]; then
  printf "${RED}$MSG_NODE_OLD${NC}\n" "$NODE_VER"
  exit 1
fi
printf "${GREEN}$MSG_NODE_OK${NC}\n" "$NODE_VER"

# Check OpenClaw
if ! command -v openclaw &>/dev/null; then
  echo -e "${RED}$MSG_OC_MISSING${NC}"
  exit 1
fi

OC_VER=$(openclaw --version 2>/dev/null | head -1 || echo "unknown")
printf "${GREEN}$MSG_OC_OK${NC}\n" "$OC_VER"
echo ""

# --- Step 2: Choose install method ---
INSTALL_METHOD="1"
if [ -t 0 ]; then
  echo -e "${YELLOW}$MSG_MODE_TITLE${NC}"
  echo -e "$MSG_MODE_1"
  echo -e "$MSG_MODE_2"
  printf "$MSG_MODE_PROMPT"
  read -r choice
  if [ "$choice" = "2" ]; then
    INSTALL_METHOD="2"
  fi
fi
echo ""

# --- Step 3: Install ---
PLUGIN_DIR="${HOME}/.openclaw/plugins/clawguard"

if [ -d "$PLUGIN_DIR" ]; then
  echo -e "${YELLOW}$MSG_ALREADY${NC}"
  rm -rf "$PLUGIN_DIR"
fi

mkdir -p "${HOME}/.openclaw/plugins"

if [ "$INSTALL_METHOD" = "1" ]; then
  echo -e "${BLUE}$MSG_NPM${NC}"
  cd /tmp
  rm -rf clawguard-npm-install
  mkdir clawguard-npm-install && cd clawguard-npm-install
  npm pack clawguard 2>/dev/null && {
    tar xzf clawguard-*.tgz
    mv package "$PLUGIN_DIR"
  } || {
    # Fallback to git clone if npm not published yet
    echo -e "${BLUE}$MSG_CLONE${NC}"
    git clone --depth 1 https://github.com/jnMetaCode/clawguard.git "$PLUGIN_DIR" 2>/dev/null
    rm -rf "$PLUGIN_DIR/.git"
  }
  cd /tmp && rm -rf clawguard-npm-install
else
  echo -e "${BLUE}$MSG_CLONE${NC}"
  git clone --depth 1 https://github.com/jnMetaCode/clawguard.git "$PLUGIN_DIR" 2>/dev/null
  rm -rf "$PLUGIN_DIR/.git"
fi

# Fix ownership
if [ "$(id -u)" = "0" ]; then
  chown -R root:root "$PLUGIN_DIR"
fi

echo ""

# --- Step 4: Verify ---
echo -e "${BLUE}$MSG_VERIFY${NC}"
if [ -f "$PLUGIN_DIR/src/index.ts" ] && [ -f "$PLUGIN_DIR/openclaw.plugin.json" ]; then
  echo -e "${GREEN}$MSG_SUCCESS${NC}"
else
  echo -e "${RED}Installation failed — files missing${NC}"
  exit 1
fi

echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}$MSG_DONE${NC}"
echo ""
echo -e "${YELLOW}$MSG_USAGE${NC}"
echo -e "$MSG_CMD1"
echo -e "$MSG_CMD2"
echo -e "$MSG_CMD3"
echo -e "$MSG_CMD4"
echo ""
echo -e "${YELLOW}$MSG_CONFIG${NC}"
cat <<'CONF'
  # ~/.openclaw/openclaw.json → plugins section:
  {
    "plugins": {
      "entries": {
        "clawguard": { "enabled": true }
      }
    }
  }
CONF
echo ""
echo -e "${BLUE}$MSG_DOCS${NC}"
echo ""
