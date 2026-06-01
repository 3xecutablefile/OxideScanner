#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; exit 1; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

echo -e "${BLUE}━━━ OxideScanner Installer ━━━${NC}"

[ -f Cargo.toml ] && [ -f src/main.rs ] || fail "Run from OxideScanner repo root"

ARCH=$(uname -m)
case "$OSTYPE" in
  linux-gnu*)  OS=linux;;
  darwin*)     OS=macos;;
  *)           fail "Unsupported OS: $OSTYPE";;
esac
info "Detected: $OS / $ARCH"

if ! cmd_exists cargo; then
  info "Installing Rust..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  . "$HOME/.cargo/env"
  ok "Rust installed"
else
  ok "Rust already installed"
fi

install_pkg() {
  local pkg=$1 cmd=$2
  cmd_exists "$cmd" && { ok "$pkg already installed"; return; }
  info "Installing $pkg..."
  case $OS in
    linux)
      for pm in apt-get dnf yum; do
        cmd_exists $pm && { sudo $pm install -y "$pkg" 2>/dev/null; return; }
      done
      fail "No package manager found";;
    macos)
      if cmd_exists brew; then brew install "$pkg"
      else fail "Homebrew required: https://brew.sh"; fi;;
  esac
}

install_searchsploit() {
  [ "$OS" = linux ] && { sudo apt-get install -y exploitdb 2>/dev/null && return; }
  [ "$OS" = macos ] && { brew install exploitdb 2>/dev/null && return; }
  sudo git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit
  sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/
}

install_pkg nmap nmap
cmd_exists searchsploit && ok "searchsploit already installed" || install_searchsploit

pick_install_dir() {
  cmd_exists oxscan && { echo "$(command -v oxscan)"; return; }

  [ "$ARCH" = arm64 ] && [ -d /opt/homebrew/bin ] && [ -w /opt/homebrew/bin ] \
    && echo "/opt/homebrew/bin" && return

  [ -d /usr/local/bin ] && [ -w /usr/local/bin ] && echo "/usr/local/bin" && return

  for d in "$HOME/.local/bin" "$HOME/.cargo/bin"; do
    [ -d "$d" ] && [[ ":$PATH:" == *":$d:"* ]] && echo "$d" && return
  done

  [[ ":$PATH:" == *":$HOME/.local/bin:"* ]] && {
    mkdir -p "$HOME/.local/bin"
    echo "$HOME/.local/bin"
    return
  }

  echo ""
}

info "Building..."
cargo build --release
ok "Build complete"

DEST=$(pick_install_dir)
if [ -n "$DEST" ]; then
  if [[ "$DEST" == *"/usr/local/bin"* ]] && [ ! -w /usr/local/bin ]; then
    sudo cp target/release/oxscan "$DEST"
    sudo chmod +x "$DEST"
  else
    cp target/release/oxscan "$DEST"
    chmod +x "$DEST"
  fi
  ok "Installed to $DEST"
else
  warn "Could not find a PATH directory (try adding ~/.local/bin to PATH)"
  info "Binary: $(pwd)/target/release/oxscan"
  info "  sudo cp target/release/oxscan /usr/local/bin/"
fi

echo ""
echo -e "${GREEN}━━━ Done ━━━${NC}"
cmd_exists nmap         && ok "nmap"         || warn "nmap missing"
cmd_exists searchsploit && ok "searchsploit" || warn "searchsploit missing"

if cmd_exists oxscan; then
  ok "oxscan ready"
  echo ""
  echo "  oxscan scanme.nmap.org"
  echo "  oxscan scanme.nmap.org --udp"
  echo "  oxscan scanme.nmap.org --script vuln"
else
  echo ""
  echo "  ./target/release/oxscan scanme.nmap.org"
fi
