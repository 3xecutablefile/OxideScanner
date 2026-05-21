#!/bin/bash

# OxideScanner Installation Script
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   OxideScanner Installation v1.0.1     ${NC}"
echo -e "${BLUE}   Intelligent Exploit Discovery        ${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -f "src/main.rs" ]; then
    print_error "Please run from OxideScanner repository root"
    exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported OS: $OSTYPE"
    exit 1
fi

print_info "Detected OS: $OS"

# Check if command exists
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# Install package
install_pkg() {
    local pkg=$1 cmd=$2
    if cmd_exists "$cmd"; then
        print_success "$pkg already installed"
        return
    fi
    
    print_info "Installing $pkg..."
    
    if [ "$OS" = "linux" ]; then
        if cmd_exists apt-get; then
            sudo apt-get update && sudo apt-get install -y "$pkg"
        elif cmd_exists yum; then
            sudo yum install -y "$pkg"
        elif cmd_exists dnf; then
            sudo dnf install -y "$pkg"
        else
            print_error "No supported package manager found"
            exit 1
        fi
    elif [ "$OS" = "macos" ]; then
        if cmd_exists brew; then
            brew install "$pkg"
        else
            print_error "Homebrew required. Install from https://brew.sh"
            exit 1
        fi
    fi
}

# Install Rust
if ! cmd_exists cargo; then
    print_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    print_success "Rust installed"
else
    print_success "Rust already installed"
fi

# Install dependencies
print_info "Installing dependencies..."
install_pkg "nmap" "nmap"
install_pkg "Ruby" "ruby"

# Install searchsploit
if ! cmd_exists searchsploit; then
    print_info "Installing searchsploit..."
    if [ "$OS" = "linux" ]; then
        sudo apt-get install -y exploitdb 2>/dev/null || {
            # Manual installation
            sudo git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit
            sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/
        }
    elif [ "$OS" = "macos" ]; then
        brew install exploitdb 2>/dev/null || {
            sudo git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit
            sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/
        }
    fi
    print_success "searchsploit installed"
else
    print_success "searchsploit already installed"
fi

# Build OxideScanner
print_info "Building OxideScanner v1.0.1..."
print_info "Features: Intelligent query filtering + Real exploit data"
cargo build --release
print_success "Build complete"

# Install binary
print_info "Installing to system..."
INSTALL_DIR="/usr/local/bin"
if [ -w "$INSTALL_DIR" ] || sudo -n true 2>/dev/null; then
    sudo cp target/release/oxscan "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/oxscan"
    print_success "Installed to $INSTALL_DIR"
else
    print_warning "Cannot install to system PATH"
    print_info "Binary available at: $(pwd)/target/release/oxscan"
fi

# Final verification
echo -e "\n${GREEN}Installation Summary:${NC}"
cmd_exists nmap && print_success "nmap" || print_error "nmap"
cmd_exists searchsploit && print_success "searchsploit" || print_warning "searchsploit"

if cmd_exists oxscan; then
    print_success "oxscan (system)"
    echo -e "\n${GREEN}Ready to scan!${NC}"
    echo "  oxscan scanme.nmap.org"
    echo "  oxscan scanme.nmap.org -5k --json"
    echo ""
    echo "${BLUE}New in v1.0.1:${NC}"
    echo "  ✨ Intelligent exploit search - No more false positives"
    echo "  🎯 Only searches when specific service info is available"
    echo "  ⚡ Real searchsploit data instead of thousands of irrelevant results"
else
    print_success "oxscan (local)"
    echo -e "\n${GREEN}Ready to scan!${NC}"
    echo "  ./target/release/oxscan scanme.nmap.org"
fi

echo -e "\n${GREEN}Happy hacking! 🚀${NC}"