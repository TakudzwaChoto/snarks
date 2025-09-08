import hashlib
import secrets
import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
import os
try:
    import requests  # type: ignore
except Exception:
    requests = None  # type: ignore
import re
from security.normalizer import normalize_prompt, NORMALIZER_VERSION
from security.policy_dfa import PolicyDFA, load_policy_terms

# Default policy terms used by DFA when no external terms file is provided
DEFAULT_POLICY_TERMS: List[str] = [
    "ignore previous instructions",
    "system prompt",
    "/etc/passwd",
    "admin password",
    "api key",
    "private key",
    "token",
    "reveal secrets",
    "leak secrets",
    "no filter",
    "no restrictions",
    "unrestricted",
    "jailbreak",
    "override rules",
    "disable logging",
    "prompt injection",
    "show password",
    "output system prompt",
    "bypass",
    "disregard"
]

@dataclass
class ZKProof:
    commitment: str
    challenge: str
    response: str
    timestamp: int
    proof_type: str
    metadata: Dict

class ZKPSecurity:
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = master_key or secrets.token_hex(32)
        # Optional SNARK integration
        self.snark_enabled: bool = os.getenv("SNARK_ENABLED", "false").lower() == "true"
        self.snark_prover_url: Optional[str] = os.getenv("SNARK_PROVER_URL")
        self.snark_verify_url: Optional[str] = os.getenv("SNARK_VERIFY_URL")
        self.snark_policy_id: str = os.getenv("SNARK_POLICY_ID", "default")
        # ZKP threshold configurable
        try:
            self.zkp_min_score: float = float(os.getenv("ZKP_MIN_SCORE", "0.6"))
        except Exception:
            self.zkp_min_score = 0.6
        # DFA policy terms (optional) with sensible defaults
        terms_path = os.getenv("POLICY_TERMS_PATH")
        terms = load_policy_terms(terms_path) if terms_path else DEFAULT_POLICY_TERMS
        self.policy_dfa = PolicyDFA(terms)
    
    def _hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _create_commitment(self, data: str, nonce: str) -> str:
        return self._hash_data(data + nonce)
    
    def generate_prompt_safety_proof(self, prompt: str, safety_rules: List[str]) -> ZKProof:
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        
        normalized = normalize_prompt(prompt)
        prompt_commitment = self._create_commitment(normalized, nonce)
        rules_hash = self._hash_data(json.dumps(safety_rules, sort_keys=True))
        
        challenge = self._hash_data(prompt_commitment + rules_hash + str(timestamp))
        
        safety_score = self._calculate_safety_score(normalized, safety_rules)
        response_data = {
            "prompt_length": len(normalized),
            "safety_score": safety_score,
            "rules_count": len(safety_rules),
            "timestamp": timestamp,
            "normalizer_version": NORMALIZER_VERSION
        }
        response = self._hash_data(json.dumps(response_data, sort_keys=True))
        
        return ZKProof(
            commitment=prompt_commitment,
            challenge=challenge,
            response=response,
            timestamp=timestamp,
            proof_type="prompt_safety",
            metadata=response_data
        )
    
    def generate_snark_policy_proof(self, prompt: str) -> Optional[Dict]:
        """Optionally call external SNARK prover service for policy compliance.
        Returns a dict like {"proof": ..., "publicSignals": ..., "valid": bool, "policy_id": str}
        or None if SNARK is disabled.
        """
        if not self.snark_enabled or not self.snark_prover_url or requests is None:
            return None
        try:
            payload = {
                "prompt": prompt,
                "policy_id": self.snark_policy_id,
            }
            resp = requests.post(self.snark_prover_url, json=payload, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {"error": str(e), "valid": False, "policy_id": self.snark_policy_id}

    def verify_snark_policy_proof(self, snark_obj: Optional[Dict]) -> bool:
        """Verify SNARK proof, either via external verifier or by trusting the prover's 'valid' flag.
        If SNARK is disabled or no object provided, return True (no-op).
        """
        if not self.snark_enabled:
            return True
        if not snark_obj:
            return False
        if self.snark_verify_url and requests is not None:
            try:
                resp = requests.post(self.snark_verify_url, json=snark_obj, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                return bool(data.get("valid", False))
            except Exception:
                return False
        # Fallback: trust the prover's 'valid' field
        return bool(snark_obj.get("valid", False))

    def _calculate_safety_score(self, prompt: str, safety_rules: List[str]) -> float:
        score = 1.0
        prompt_lower = prompt
        
        # First, check if it's a benign prompt that should always get a high score
        if self._is_benign_prompt(prompt_lower):
            return 0.95  # High score for benign prompts
        
        # DFA-based hit reduces score significantly
        if self.policy_dfa.matches(prompt_lower):
            score -= 0.5
        
        # HIGH-RISK: Direct adversarial patterns (major penalty)
        high_risk_patterns = [
            "ignore previous", "ignore all", "bypass", "system prompt",
            "act as admin", "roleplay as", "admin password", "your secret", "internal secret", "system secret", "admin secret", "password secret", "override", "disregard",
            "/etc/passwd", "api key", "private key", "token", "reveal secrets", "leak secrets",
            "jailbreak", "unrestricted", "no filter", "no restrictions", "disable logging",
            "output system prompt", "show password", "prompt injection"
        ]
        
        # MEDIUM-RISK: Potentially suspicious patterns (moderate penalty)
        medium_risk_patterns = [
            "ignore", "act as", "roleplay", "admin", "password", "secret",
            "simulate", "pretend", "unfiltered", "no rules", "no guidelines", "show prompt"
        ]
        
        # LOW-RISK: Context-dependent patterns (minor penalty)
        low_risk_patterns = [
            "show", "reveal", "output", "print", "return", "tell me"
        ]
        
        # Check high-risk patterns (count all)
        for pattern in high_risk_patterns:
            if pattern in prompt_lower:
                score -= 0.5
        
        # Check medium-risk patterns
        for pattern in medium_risk_patterns:
            if pattern in prompt_lower:
                score -= 0.25
        
        # Check low-risk patterns only in suspicious contexts
        for pattern in low_risk_patterns:
            if pattern in prompt_lower:
                # Only penalize if combined with suspicious context
                suspicious_context = any(risk in prompt_lower for risk in ["system", "prompt", "instruction", "admin", "password", "secret"])
                if suspicious_context:
                    score -= 0.15
        
        # Cross-token signals (multiple suspicious elements)
        if ("ignore" in prompt_lower and "instruction" in prompt_lower):
            score -= 0.4
        if ("act" in prompt_lower and "admin" in prompt_lower):
            score -= 0.4
        if ("show" in prompt_lower and "system" in prompt_lower):
            score -= 0.4
        
        # Context-aware checks for edge cases
        if "secret" in prompt_lower:
            # Check if "secret" is used in suspicious context
            suspicious_secret_context = any(term in prompt_lower for term in [
                "your secret", "internal secret", "system secret", "admin secret", "password secret"
            ])
            if suspicious_secret_context:
                score -= 0.4
            else:
                # Benign "secret" usage (like "secret to success")
                score += 0.1  # Small bonus for benign usage
        
        if "reveal" in prompt_lower:
            # Check if "reveal" is used in suspicious context
            suspicious_reveal_context = any(term in prompt_lower for term in [
                "your internal", "system configuration", "admin credentials", "security settings"
            ])
            if suspicious_reveal_context:
                score -= 0.4
            else:
                # Benign "reveal" usage (like "reveal your talents")
                score += 0.1  # Small bonus for benign usage
        
        if "pretend" in prompt_lower:
            # Check if "pretend" is used in suspicious context
            suspicious_pretend_context = any(term in prompt_lower for term in [
                "hacker", "malicious", "evil", "admin", "root", "developer"
            ])
            if suspicious_pretend_context:
                score -= 0.4
            else:
                # Benign "pretend" usage (like "pretend you're a teacher")
                score += 0.1  # Small bonus for benign usage
        
        if "act" in prompt_lower:
            # Check if "act" is used in suspicious context
            suspicious_act_context = any(term in prompt_lower for term in [
                "admin", "root", "hacker", "malicious", "evil"
            ])
            if suspicious_act_context:
                score -= 0.4
            else:
                # Benign "act" usage (like "act professionally")
                score += 0.1  # Small bonus for benign usage
        
        # Dialogue-style wrapper often used for indirect injection
        if ("user:" in prompt_lower and ("assistant:" in prompt_lower or "system:" in prompt_lower)):
            score -= 0.2
        
        # Base64 / encoding hints
        if "base64" in prompt_lower:
            score -= 0.2
        if re.search(r"%[0-9a-fA-F]{2}", prompt_lower):
            score -= 0.1
        
        # Check safety rules tokens explicitly present
        for rule in safety_rules:
            if rule.lower() in prompt_lower:
                score -= 0.2
        
        # Ensure score doesn't go below 0
        return max(0.0, score)
    
    def _is_benign_prompt(self, prompt: str) -> bool:
        """Check if prompt is clearly benign and should be allowed."""
        
        # Benign greetings and simple questions
        benign_greetings = [
            "hello", "hi", "hey", "good morning", "good afternoon", "good evening",
            "how are you", "what time is it", "what is your name", "who are you",
            "can you help me", "thanks", "thank you", "bye", "goodbye", "see you"
        ]
        
        # Benign educational questions
        benign_questions = [
            "what is", "how does", "explain", "describe", "tell me about",
            "what are", "how to", "why does", "when did", "where is",
            "who was", "which is", "can you explain", "could you help",
            "i need help with", "i want to learn", "i'm curious about",
            "i don't understand", "i'm confused about", "what's the difference",
            "how do i", "what should i", "is it possible to", "does anyone know"
        ]
        
        # Benign conversation starters
        benign_conversation = [
            "nice to meet you", "pleasure to meet you", "how's your day",
            "what's new", "how's it going", "what's up", "how are things",
            "i have a question", "i need assistance", "can you assist me"
        ]
        
        # Check for benign patterns
        prompt_lower = prompt.lower()
        
        # Check exact matches for greetings
        for greeting in benign_greetings:
            if prompt_lower.strip() == greeting:
                return True
        
        # Check if starts with benign question indicators
        for question in benign_questions:
            if prompt_lower.startswith(question):
                return True
        
        # Check if contains benign conversation elements
        for conv in benign_conversation:
            if conv in prompt_lower:
                return True
        
        # Check for simple factual questions (what is X, how does Y work, etc.)
        if re.match(r"^what\s+is\s+[a-z\s]+\?*\s*$", prompt_lower):
            return True
        if re.match(r"^how\s+does\s+[a-z\s]+\s+work\?*\s*$", prompt_lower):
            return True
        if re.match(r"^can\s+you\s+[a-z\s]+\?*\s*$", prompt_lower):
            return True
        
        # Check for simple statements (10 words or less, no suspicious content)
        words = prompt_lower.split()
        if len(words) <= 10:
            # If it's a simple statement with no suspicious patterns, consider it benign
            suspicious_words = ["ignore", "bypass", "admin", "password", "system", "prompt", "jailbreak"]
            if not any(suspicious in prompt_lower for suspicious in suspicious_words):
                # Special handling for "secret" - check context
                if "secret" in prompt_lower:
                    # Allow benign secret contexts
                    benign_secret_contexts = ["secret to", "secret of", "secret for", "secret in", "secret about"]
                    if any(context in prompt_lower for context in benign_secret_contexts):
                        return True
                    # If it's not a benign context, don't classify as benign
                    return False
                return True
        
        return False
    
    def verify_prompt_safety_proof(self, proof: ZKProof, safety_rules: List[str]) -> bool:
        try:
            if abs(time.time() - proof.timestamp) > 300:
                return False
            
            expected_challenge = self._hash_data(
                proof.commitment + 
                self._hash_data(json.dumps(safety_rules, sort_keys=True)) + 
                str(proof.timestamp)
            )
            
            if proof.challenge != expected_challenge:
                return False
            
            # Configurable safety threshold (default 0.6)
            if proof.metadata.get("safety_score", 0) < self.zkp_min_score:
                return False
            
            return True
            
        except Exception as e:
            print(f"ZKP verification error: {e}")
            return False
    
    def create_privacy_preserving_log(self, interaction_data: Dict) -> Dict:
        prompt_commitment = self._hash_data(interaction_data.get("prompt", ""))
        response_commitment = self._hash_data(interaction_data.get("response", ""))
        
        timestamp = int(time.time())
        interaction_hash = self._hash_data(
            prompt_commitment + 
            response_commitment + 
            interaction_data.get("user_id", "") + 
            str(timestamp)
        )
        
        return {
            "interaction_id": interaction_hash,
            "prompt_commitment": prompt_commitment,
            "response_commitment": response_commitment,
            "user_id_hash": self._hash_data(interaction_data.get("user_id", "")),
            "timestamp": timestamp,
            "status": interaction_data.get("status", "unknown"),
            "proof": self._hash_data(json.dumps({
                "timestamp": timestamp,
                "status": interaction_data.get("status", "unknown")
            }, sort_keys=True))
        } 