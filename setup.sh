#!/bin/bash

# Advanced Reconnaissance Suite Setup Script
# This script helps set up the environment and dependencies

set -e  # Exit on any error

echo "🔍 Advanced Reconnaissance Suite Setup"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    print_info "Detected Linux system"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_info "Detected macOS system"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check and install system dependencies
install_system_dependencies() {
    print_info "Installing system dependencies..."
    
    if [[ "$OS" == "linux" ]]; then
        # Detect Linux distribution
        if command_exists apt-get; then
            print_info "Using apt package manager"
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv nmap nikto whois dnsutils wget curl git
            
            # Install Chrome/Chromium for screenshots
            if ! command_exists google-chrome && ! command_exists chromium-browser; then
                print_info "Installing Chromium browser..."
                sudo apt-get install -y chromium-browser chromium-chromedriver
            fi
            
        elif command_exists yum; then
            print_info "Using yum package manager"
            sudo yum install -y python3 python3-pip nmap nikto whois bind-utils wget curl git
            
        elif command_exists dnf; then
            print_info "Using dnf package manager"
            sudo dnf install -y python3 python3-pip nmap nikto whois bind-utils wget curl git
            
        else
            print_error "Unsupported Linux package manager"
            exit 1
        fi
        
    elif [[ "$OS" == "macos" ]]; then
        if command_exists brew; then
            print_info "Using Homebrew package manager"
            brew install python3 nmap nikto whois wget curl git
        else
            print_error "Homebrew not found. Please install Homebrew first:"
            print_error "/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            exit 1
        fi
    fi
}

# Setup Python virtual environment
setup_python_environment() {
    print_info "Setting up Python virtual environment..."
    
    # Check if Python 3 is available
    if ! command_exists python3; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    # Create virtual environment
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        print_status "Created virtual environment"
    else
        print_warning "Virtual environment already exists"
    fi
    
    # Activate virtual environment and install requirements
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python dependencies
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        print_status "Installed Python dependencies"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Create necessary directories
create_directories() {
    print_info "Creating necessary directories..."
    
    mkdir -p reports
    mkdir -p reports/screenshots
    mkdir -p reports/vuln
    mkdir -p config
    mkdir -p templates
    mkdir -p static
    
    print_status "Created directory structure"
}

# Set file permissions
set_permissions() {
    print_info "Setting file permissions..."
    
    chmod +x *.py
    chmod +x setup.sh
    
    print_status "Set executable permissions"
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Check Python modules
    python3 -c "
import sys
modules = ['requests', 'dns.resolver', 'whois', 'nmap', 'selenium', 'flask', 'jinja2']
missing = []
for module in modules:
    try:
        __import__(module)
        print(f'✓ {module}')
    except ImportError:
        print(f'✗ {module}')
        missing.append(module)

if missing:
    print(f'Missing modules: {missing}')
    sys.exit(1)
else:
    print('All Python modules installed successfully')
"
    
    # Check system tools
    for tool in nmap nikto whois dig; do
        if command_exists $tool; then
            print_status "$tool is available"
        else
            print_warning "$tool is not available"
        fi
    done
}

# Create sample configuration
create_sample_config() {
    print_info "Creating sample configuration..."
    
    cat > config/sample.env << 'EOF'
# Sample environment configuration
# Copy this to .env and fill in your API keys

# Shodan API Key (optional)
# Get your key from: https://account.shodan.io/
SHODAN_API_KEY=your_shodan_api_key_here

# Flask configuration
FLASK_ENV=development
FLASK_DEBUG=true

# Report settings
DEFAULT_OUTPUT_FORMAT=json
MAX_SUBDOMAINS=100
SCREENSHOT_TIMEOUT=30
EOF
    
    print_status "Created sample configuration file"
}

# Main installation process
main() {
    print_info "Starting Advanced Reconnaissance Suite setup..."
    
    # Check if we're in the right directory
    if [[ ! -f "basic_recon.py" ]]; then
        print_error "Please run this script from the reconnaissance suite directory"
        exit 1
    fi
    
    # Install system dependencies
    install_system_dependencies
    
    # Setup Python environment
    setup_python_environment
    
    # Create directories
    create_directories
    
    # Set permissions
    set_permissions
    
    # Create sample config
    create_sample_config
    
    # Verify installation
    verify_installation
    
    echo ""
    echo "======================================"
    print_status "Setup completed successfully!"
    echo "======================================"
    echo ""
    print_info "To get started:"
    echo "  1. Activate the virtual environment: source venv/bin/activate"
    echo "  2. Run a basic scan: python3 basic_recon.py example.com"
    echo "  3. Start the web interface: python3 app.py"
    echo "  4. Access web UI at: http://localhost:5000"
    echo ""
    print_info "Optional:"
    echo "  - Copy config/sample.env to config/.env and add your API keys"
    echo "  - Run the test suite: python3 test_suite.py"
    echo ""
    print_warning "Remember to only scan domains you own or have permission to test!"
}

# Run main function
main "$@"
