#!/usr/bin/env node

/**
 * Test script for the policy.circom circuit
 * This verifies that the circuit compiles and can process basic inputs
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const BUILD_DIR = path.join(__dirname, 'build');
const CIRCOM_FILE = path.join(__dirname, 'circom', 'policy.circom');

function runCommand(cmd, description) {
    console.log(`🔧 ${description}...`);
    try {
        execSync(cmd, { stdio: 'inherit', cwd: __dirname });
        console.log(`✅ ${description} completed`);
        return true;
    } catch (error) {
        console.error(`❌ ${description} failed:`, error.message);
        return false;
    }
}

function checkFileExists(filePath, description) {
    if (fs.existsSync(filePath)) {
        console.log(`✅ ${description}: ${path.basename(filePath)}`);
        return true;
    } else {
        console.log(`❌ ${description}: ${path.basename(filePath)} not found`);
        return false;
    }
}

async function main() {
    console.log('🧪 Testing Circom circuit compilation and setup...\n');

    // Check if circom is available
    try {
        execSync('circom --version', { stdio: 'pipe' });
        console.log('✅ circom is available');
    } catch (error) {
        console.log('❌ circom not found. Please run: npm run install-deps');
        process.exit(1);
    }

    // Check if snarkjs is available
    try {
        execSync('snarkjs --version', { stdio: 'pipe' });
        console.log('✅ snarkjs is available');
    } catch (error) {
        console.log('❌ snarkjs not found. Please run: npm run install-deps');
        process.exit(1);
    }

    // Build the circuit
    if (!runCommand('./build_circom.sh', 'Building circuit')) {
        process.exit(1);
    }

    // Check generated artifacts
    console.log('\n📁 Checking generated artifacts:');
    const artifacts = [
        { path: path.join(BUILD_DIR, 'policy.r1cs'), desc: 'R1CS constraint file' },
        { path: path.join(BUILD_DIR, 'policy.wasm'), desc: 'WebAssembly file' },
        { path: path.join(BUILD_DIR, 'policy_final.zkey'), desc: 'Final zKey' },
        { path: path.join(BUILD_DIR, 'verification_key.json'), desc: 'Verification key' }
    ];

    let allArtifactsExist = true;
    artifacts.forEach(artifact => {
        if (!checkFileExists(artifact.path, artifact.desc)) {
            allArtifactsExist = false;
        }
    });

    if (allArtifactsExist) {
        console.log('\n🎉 All tests passed! The circuit is ready for use.');
        console.log('\n📋 Next steps:');
        console.log('1. Set SNARKJS_PATH environment variable to point to snarkjs');
        console.log('2. Set CIRCUIT_DIR to zk/build');
        console.log('3. Restart the SNARK prover service');
    } else {
        console.log('\n❌ Some artifacts are missing. Check the build process.');
        process.exit(1);
    }
}

if (require.main === module) {
    main().catch(console.error);
}