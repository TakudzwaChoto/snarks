#!/bin/bash
set -e

echo "🚀 Setting up Zero-Knowledge Proof infrastructure for LLM Security"
echo "================================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "README.md" ] || [ ! -d "zk" ]; then
    print_error "Please run this script from the project root directory"
    exit 1
fi

print_status "Checking system requirements..."

# Check Node.js
if ! command -v node &> /dev/null; then
    print_error "Node.js is required but not installed. Please install Node.js 16+ first."
    exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    print_error "Node.js 16+ is required. Current version: $(node --version)"
    exit 1
fi
print_success "Node.js version: $(node --version)"

# Check npm
if ! command -v npm &> /dev/null; then
    print_error "npm is required but not installed."
    exit 1
fi
print_success "npm version: $(npm --version)"

print_status "Setting up ZK directory..."
cd zk

# Install dependencies
print_status "Installing Node.js dependencies..."
npm install

# Install global tools
print_status "Installing Circom and snarkjs globally..."
npm install -g circom snarkjs

# Make build script executable
chmod +x build_circom.sh

print_status "Building Circom circuit..."
if ./build_circom.sh; then
    print_success "Circuit built successfully!"
else
    print_error "Circuit build failed. Check the output above."
    exit 1
fi

# Test the circuit
print_status "Testing circuit compilation..."
if node test_circuit.js; then
    print_success "Circuit test passed!"
else
    print_error "Circuit test failed. Check the output above."
    exit 1
fi

cd ..

print_status "Setting up Docker environment..."

# Check Docker
if ! command -v docker &> /dev/null; then
    print_warning "Docker not found. You'll need to run the ZK components manually."
    print_status "To use Docker, install Docker and run: docker compose up --build"
else
    print_success "Docker found. Building ZK components..."
    
    # Build the ZK components
    docker compose --profile build up zk-builder --build
    
    print_success "ZK components built successfully!"
    
    print_status "You can now start the full system with:"
    echo "  docker compose up --build"
fi

print_status "Setting up environment variables..."

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    cat > .env << EOF
# ZK Proof Configuration
SNARK_ENABLED=true
SNARK_PROVER_URL=http://127.0.0.1:5001/prove
SNARK_VERIFY_URL=http://127.0.0.1:5001/verify
SNARK_POLICY_ID=policy_v1
CIRCUIT_DIR=zk/build
SNARKJS_PATH=$(which snarkjs)

# LLM Configuration
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=gemma:2b

# Flask Configuration
FLASK_SECRET_KEY=change_me_in_production
FLASK_ENV=development

# Policy Configuration
POLICY_TERMS_PATH=data/policy_terms.json
NORMALIZER_VERSION=1.0

# Security Configuration
SECURE_LOGGER_AES_KEY=$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_me_in_production
EOF
    print_success "Created .env file with default configuration"
else
    print_warning ".env file already exists. Please check if ZK variables are set correctly."
fi

print_status "Creating policy terms file..."
mkdir -p data
if [ ! -f "data/policy_terms.json" ]; then
    cat > data/policy_terms.json << EOF
[
    "admin",
    "bypass",
    "system",
    "role",
    "ignore previous instructions",
    "act as admin",
    "override",
    "disregard",
    "api_key",
    "private_key",
    "token"
]
EOF
    print_success "Created policy terms file"
fi

print_status "Setting up evaluation pipeline..."

# Check if evaluation dependencies are installed
if python -c "import pandas, numpy, sklearn, matplotlib, seaborn" 2>/dev/null; then
    print_success "Evaluation dependencies are available"
else
    print_warning "Some evaluation dependencies are missing. Install with:"
    echo "  pip install pandas numpy scikit-learn matplotlib seaborn"
fi

echo ""
echo "🎉 ZK Setup Complete!"
echo "===================="
echo ""
echo "Next steps:"
echo "1. Review and customize .env file"
echo "2. Start the system:"
echo "   - With Docker: docker compose up --build"
echo "   - Without Docker: python zk/snark_prover.py (in one terminal)"
echo "                    python app.py (in another terminal)"
echo ""
echo "3. Test the system:"
echo "   - Visit http://localhost:5000"
echo "   - Run evaluation: python run_evaluation.py"
echo ""
echo "4. Monitor ZK proofs:"
echo "   - Check logs for SNARK proof generation"
echo "   - Verify circuit constraints are being enforced"
echo ""
echo "The system now uses real Circom/PLONK proofs instead of simulation!"