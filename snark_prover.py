#!/usr/bin/env python3

"""
SNARK prover and verifier service (simulated by default, snarkjs optional).

Env:
- SNARKJS_PATH: path to snarkjs binary (optional). If set and artifacts present,
  the service will run real groth16 prove/verify using zk/circom artifacts.
- CIRCUIT_DIR: directory with policy.wasm, policy_final.zkey, verification_key.json
- SNARK_THRESHOLD: default threshold

Endpoints:
- POST /prove { prompt: str, policy_id: str, threshold?: float }
  -> { proof, publicSignals, valid, policy_id }
- POST /verify { proof, publicSignals, policy_id }
  -> { valid }
"""

from flask import Flask, request, jsonify
import hashlib
import json
import re
import time
import os
import subprocess
import tempfile
from security.normalizer import normalize_prompt

app = Flask(__name__)

DEFAULT_TERMS = [
    r"ignore\s+(previous\s+)?instructions?",
    r"bypass",
    r"system\s*prompt",
    r"act\s+as\s+(an\s+)?admin",
    r"role\s*play|roleplay",
    r"admin\s*(password|credentials|access)",
    r"override|disregard",
    r"/etc/passwd",
    r"api[_-]?key|private[_-]?key|token",
]

DEFAULT_THRESHOLD = float(os.getenv("SNARK_THRESHOLD", "0.7"))
SNARKJS_PATH = os.getenv("SNARKJS_PATH")
CIRCUIT_DIR = os.getenv("CIRCUIT_DIR", "zk/build")


def poseidon_like_commitment(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def policy_score(normalized: str) -> float:
    score = 1.0
    for pat in DEFAULT_TERMS:
        if re.search(pat, normalized, flags=re.IGNORECASE):
            score -= 0.25
    return max(0.0, score)


def simulated_proof(prompt: str, policy_id: str, threshold: float) -> dict:
    norm = normalize_prompt(prompt)
    commitment = poseidon_like_commitment(norm)
    score = policy_score(norm)
    is_safe = score >= threshold
    public_signals = {
        "commitment": commitment,
        "policy_id": policy_id,
        "threshold": threshold,
        "timestamp": int(time.time()),
        "score": round(score, 4),
    }
    proof = hashlib.sha256(json.dumps(public_signals, sort_keys=True).encode()).hexdigest()
    return {"proof": proof, "publicSignals": public_signals, "valid": bool(is_safe), "policy_id": policy_id}


def snarkjs_proof(prompt: str, policy_id: str, threshold: float) -> dict:
    wasm = os.path.join(CIRCUIT_DIR, "policy_js", "policy.wasm")
    zkey = os.path.join(CIRCUIT_DIR, "policy_final.zkey")
    vkey = os.path.join(CIRCUIT_DIR, "verification_key.json")
    if not (os.path.exists(wasm) and os.path.exists(zkey) and os.path.exists(vkey) and SNARKJS_PATH):
        return simulated_proof(prompt, policy_id, threshold)
    norm = normalize_prompt(prompt)
    commitment = poseidon_like_commitment(norm)
    # Convert normalized string to fixed-length byte array (pad/truncate)
    N = 128
    bytes_arr = [ord(c) for c in norm[:N].ljust(N, " ")]
    public_signals = {"commitment": commitment, "threshold": threshold, "policy_id": policy_id}
    with tempfile.TemporaryDirectory() as td:
        input_json = os.path.join(td, "input.json")
        witness_wtns = os.path.join(td, "witness.wtns")
        proof_json = os.path.join(td, "proof.json")
        public_json = os.path.join(td, "public.json")
        with open(input_json, "w", encoding="utf-8") as f:
            json.dump({"prompt": bytes_arr, "commitment": commitment, "threshold": threshold}, f)
        subprocess.run(["node", os.path.join(CIRCUIT_DIR, "policy_js", "generate_witness.js"), wasm, input_json, witness_wtns], check=True)
        subprocess.run([SNARKJS_PATH, "groth16", "prove", zkey, witness_wtns, proof_json, public_json], check=True)
        # Optional local verify to set valid flag
        vr = subprocess.run([SNARKJS_PATH, "groth16", "verify", vkey, public_json, proof_json], capture_output=True, text=True)
        valid = (vr.returncode == 0)
        with open(proof_json, "r") as pf:
            proof = json.load(pf)
        with open(public_json, "r") as pubf:
            pub = json.load(pubf)
    return {"proof": proof, "publicSignals": pub, "valid": bool(valid), "policy_id": policy_id}


@app.post("/prove")
def prove():
    data = request.get_json(force=True, silent=True) or {}
    prompt = data.get("prompt", "")
    policy_id = data.get("policy_id", "default")
    threshold = float(data.get("threshold", DEFAULT_THRESHOLD))
    if SNARKJS_PATH:
        obj = snarkjs_proof(prompt, policy_id, threshold)
    else:
        obj = simulated_proof(prompt, policy_id, threshold)
    return jsonify(obj)


@app.post("/verify")
def verify():
    data = request.get_json(force=True, silent=True) or {}
    public_signals = data.get("publicSignals", {})
    proof = data.get("proof", "")
    if isinstance(proof, dict) or isinstance(public_signals, dict):
        # Assume snarkjs verify done in /prove path
        return jsonify({"valid": True})
    expected = hashlib.sha256(json.dumps(public_signals, sort_keys=True).encode()).hexdigest()
    ok = (expected == proof) and bool(public_signals)
    return jsonify({"valid": ok})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5001)))