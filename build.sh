#!/usr/bin/env bash
#
# Automated Build Script for FPC Disum (Honor MagicBook & Acer Swift) Linux Driver
# Targets: USB 10a5:a900 (Honor) and USB 10a5:e340 (Acer)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate linux-driver directory (works if run from repo root or inside linux-driver)
if [ -d "${SCRIPT_DIR}/linux-driver" ]; then
    DRIVER_DIR="${SCRIPT_DIR}/linux-driver"
elif [ -f "${SCRIPT_DIR}/Makefile" ] && [ -d "${SCRIPT_DIR}/src" ]; then
    DRIVER_DIR="${SCRIPT_DIR}"
else
    echo "[-] Error: Could not locate linux-driver directory!" >&2
    exit 1
fi

COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[0;31m"
COLOR_CYAN="\033[0;36m"
COLOR_RESET="\033[0m"

log_info() { echo -e "${COLOR_CYAN}[*]${COLOR_RESET} $1"; }
log_success() { echo -e "${COLOR_GREEN}[+]${COLOR_RESET} $1"; }
log_warn() { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $1"; }
log_error() { echo -e "${COLOR_RED}[-]${COLOR_RESET} $1" >&2; }

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Automated build and setup script for FPC Disum Fingerprint Driver (10a5:a900 & 10a5:e340)

Options:
  --clean           Clean build artifacts
  --install-udev    Install udev rules to /etc/udev/rules.d/ and reload udev
  --deps            Install missing build dependencies automatically
  --all             Build driver and install udev rules
  --help, -h        Show this help message

Default action (no options): Checks dependencies, compiles standalone fpc_disum_tool.
EOF
}

detect_pkg_manager() {
    if command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

install_dependencies() {
    local pm=$(detect_pkg_manager)
    log_info "Detected package manager: ${pm}"
    case "$pm" in
        dnf)
            log_info "Installing dependencies via dnf..."
            sudo dnf install -y gcc make libusb1-devel pkgconf-pkg-config
            ;;
        apt)
            log_info "Installing dependencies via apt..."
            sudo apt-get update && sudo apt-get install -y build-essential libusb-1.0-0-dev pkg-config
            ;;
        pacman)
            log_info "Installing dependencies via pacman..."
            sudo pacman -S --noconfirm base-devel libusb pkgconf
            ;;
        zypper)
            log_info "Installing dependencies via zypper..."
            sudo zypper install -y gcc make libusb-1_0-devel pkg-config
            ;;
        *)
            log_error "Unsupported package manager. Please manually install: gcc, make, libusb-1.0-dev, pkg-config"
            return 1
            ;;
    esac
}

check_dependencies() {
    local missing=0

    if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
        log_warn "C compiler (gcc/cc) is missing."
        missing=1
    fi

    if ! command -v make >/dev/null 2>&1; then
        log_warn "GNU make is missing."
        missing=1
    fi

    # Check for libusb-1.0
    if command -v pkg-config >/dev/null 2>&1; then
        if ! pkg-config --exists libusb-1.0; then
            log_warn "libusb-1.0 development headers not found via pkg-config."
            missing=1
        fi
    else
        if [ ! -f /usr/include/libusb-1.0/libusb.h ] && [ ! -f /usr/local/include/libusb-1.0/libusb.h ]; then
            log_warn "libusb-1.0 headers not found in standard include paths."
            missing=1
        fi
    fi

    if [ $missing -eq 1 ]; then
        log_error "Missing build dependencies!"
        echo
        local pm=$(detect_pkg_manager)
        echo "To install missing dependencies:"
        case "$pm" in
            dnf)    echo "  sudo dnf install gcc make libusb1-devel" ;;
            apt)    echo "  sudo apt install build-essential libusb-1.0-0-dev" ;;
            pacman) echo "  sudo pacman -S base-devel libusb" ;;
            *)      echo "  Install gcc, make, and libusb-1.0 development headers using your package manager." ;;
        esac
        echo
        echo "Or re-run this script with: $0 --deps"
        return 1
    fi

    return 0
}

build_driver() {
    log_info "Building standalone capture tool in ${DRIVER_DIR}..."
    make -C "${DRIVER_DIR}" clean
    make -C "${DRIVER_DIR}"
    
    # Copy executable to current root if run from repo root
    if [ "${DRIVER_DIR}" != "${SCRIPT_DIR}" ] && [ -f "${DRIVER_DIR}/fpc_disum_tool" ]; then
        cp -f "${DRIVER_DIR}/fpc_disum_tool" "${SCRIPT_DIR}/fpc_disum_tool"
        log_success "Binary copied to ${SCRIPT_DIR}/fpc_disum_tool"
    fi

    log_success "Build completed successfully!"
    echo
    echo -e "${COLOR_GREEN}======================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}  FPC Disum Driver Built Successfully!               ${COLOR_RESET}"
    echo -e "${COLOR_GREEN}======================================================${COLOR_RESET}"
    echo
    echo "Supported Devices:"
    echo "  - Honor MagicBook X 14 & X 16 (2024) [USB 10a5:a900]"
    echo "  - Acer Swift Series (Swift Go, Swift 21) [USB 10a5:e340]"
    echo
    echo "Next Steps:"
    echo "  1. Install udev permissions (allows non-root access):"
    echo "     sudo ./build.sh --install-udev"
    echo
    echo "  2. Test fingerprint capture:"
    echo "     ./fpc_disum_tool"
    echo
    echo "  3. Integrate into libfprint (system-wide authentication):"
    echo "     See README.md for instructions on copying src/fpc2040.c to libfprint."
    echo
}

install_udev() {
    log_info "Installing udev rules..."
    local rule_file="${DRIVER_DIR}/udev/70-libfprint-2-fpc2040.rules"
    if [ ! -f "${rule_file}" ]; then
        log_error "Udev rule file not found at ${rule_file}!"
        exit 1
    fi

    if [ "$EUID" -ne 0 ]; then
        log_warn "Root privileges required to install udev rules. Invoking sudo..."
        sudo cp -v "${rule_file}" /etc/udev/rules.d/70-libfprint-2-fpc2040.rules
        sudo udevadm control --reload-rules
        sudo udevadm trigger
    else
        cp -v "${rule_file}" /etc/udev/rules.d/70-libfprint-2-fpc2040.rules
        udevadm control --reload-rules
        udevadm trigger
    fi
    log_success "Udev rules installed and reloaded! Unplug and reconnect the device if already attached."
}

clean_build() {
    log_info "Cleaning build artifacts..."
    make -C "${DRIVER_DIR}" clean
    rm -f "${SCRIPT_DIR}/fpc_disum_tool"
    log_success "Clean completed."
}

# Argument parsing
if [ $# -eq 0 ]; then
    check_dependencies
    build_driver
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --clean)
            clean_build
            shift
            ;;
        --deps)
            install_dependencies
            check_dependencies
            build_driver
            shift
            ;;
        --install-udev)
            install_udev
            shift
            ;;
        --all)
            check_dependencies
            build_driver
            install_udev
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
done
