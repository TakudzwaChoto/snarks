#!/bin/bash
set -e

# Build script for Circom circuit
# This script compiles the policy.circom circuit and generates snarkjs artifacts

CIRCUIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCOM_FILE="$CIRCUIT_DIR/circom/policy.circom"
BUILD_DIR="$CIRCUIT_DIR/build"

echo "🔧 Building Circom circuit: $CIRCOM_FILE"

# Check if circom is installed
if ! command -v circom &> /dev/null; then
    echo "❌ circom not found. Installing..."
    npm install -g circom
fi

# Check if snarkjs is installed
if ! command -v snarkjs &> /dev/null; then
    echo "❌ snarkjs not found. Installing..."
    npm install -g snarkjs
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Compile circuit
echo "📦 Compiling circuit..."
circom "$CIRCOM_FILE" --r1cs --wasm --sym --c --output "$BUILD_DIR"

# Generate zKey (trusted setup)
echo "🔑 Generating zKey..."
snarkjs groth16 setup "$BUILD_DIR/policy.r1cs" "$BUILD_DIR/pot12_final.ptau" "$BUILD_DIR/policy_0000.zkey"

# Contribute to phase 2 (random beacon)
echo "🎲 Contributing to phase 2..."
snarkjs zkey contribute "$BUILD_DIR/policy_0000.zkey" "$BUILD_DIR/policy_final.zkey" --name="LLM Security Policy" -v

# Export verification key
echo "🔍 Exporting verification key..."
snarkjs zkey export verificationkey "$BUILD_DIR/policy_final.zkey" "$BUILD_DIR/verification_key.json"

# Generate JavaScript witness generator
echo "📱 Generating JavaScript witness generator..."
snarkjs zkey export solidityverifier "$BUILD_DIR/policy_final.zkey" "$BUILD_DIR/verifier.sol"

echo "✅ Build complete! Artifacts in: $BUILD_DIR"
echo "📁 Files generated:"
ls -la "$BUILD_DIR"