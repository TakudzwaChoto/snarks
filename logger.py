import os
import hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import sqlite3

class SecureLogger:
	def __init__(self):
		key_env = os.getenv("SECURE_LOGGER_AES_KEY")
		if key_env:
			self.aes_key = bytes.fromhex(key_env)
		else:
			os.makedirs("keys", exist_ok=True)
			key_path = os.path.join("keys", "aes.key")
			if os.path.exists(key_path):
				with open(key_path, "rb") as f:
					self.aes_key = f.read()
			else:
				self.aes_key = os.urandom(32)
				with open(key_path, "wb") as f:
					f.write(self.aes_key)
		self.private_key = self._load_ed25519_key("keys/ed25519_private.pem")
		self.public_key = self._load_ed25519_key("keys/ed25519_public.pem", private=False)
		self._ensure_multisig_schema()

	def _ensure_multisig_schema(self) -> None:
		conn = sqlite3.connect("llm_logs.db")
		cursor = conn.cursor()
		cursor.execute("PRAGMA table_info(logs)")
		cols = {row[1] for row in cursor.fetchall()}
		additions = []
		if "risk_level" not in cols:
			additions.append("ALTER TABLE logs ADD COLUMN risk_level TEXT DEFAULT 'low'")
		if "time_lock_until" not in cols:
			additions.append("ALTER TABLE logs ADD COLUMN time_lock_until TEXT")
		if "quorum_required" not in cols:
			additions.append("ALTER TABLE logs ADD COLUMN quorum_required INTEGER DEFAULT 1")
		if "status" not in cols:
			additions.append("ALTER TABLE logs ADD COLUMN status TEXT DEFAULT 'finalized'")
		for stmt in additions:
			try:
				cursor.execute(stmt)
			except Exception:
				pass
		cursor.execute(
			"""
			CREATE TABLE IF NOT EXISTS log_signatures (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				log_id INTEGER NOT NULL,
				admin_username TEXT NOT NULL,
				admin_signature TEXT NOT NULL,
				signed_at TEXT NOT NULL,
				UNIQUE(log_id, admin_username)
			)
			"""
		)
		conn.commit()
		conn.close()

	def _load_ed25519_key(self, path, private=True):
		with open(path, "rb") as f:
			if private:
				return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
			else:
				return ed25519.Ed25519PublicKey.from_public_bytes(f.read())

	def _encrypt(self, plaintext: str) -> bytes:
		nonce = os.urandom(12)
		cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce), backend=default_backend())
		encryptor = cipher.encryptor()
		ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
		return nonce + encryptor.tag + ciphertext

	def _decrypt(self, ciphertext: bytes) -> str:
		nonce, tag, ciphertext = ciphertext[:12], ciphertext[12:28], ciphertext[28:]
		cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce, tag), backend=default_backend())
		decryptor = cipher.decryptor()
		return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

	def _policy_for_risk(self, risk_level: str) -> tuple[int, str | None]:
		level = (risk_level or 'low').lower()
		if level == 'high':
			return 3, (datetime.now() + timedelta(hours=24)).isoformat()
		if level == 'medium':
			return 2, None
		return 1, None

	def log_interaction(self, user_id: str, prompt: str, response: str, *, risk_level: str = 'low') -> int:
		conn = sqlite3.connect("llm_logs.db")
		cursor = conn.cursor()
		prompt_enc = self._encrypt(prompt).hex()
		response_enc = self._encrypt(response).hex()
		cursor.execute("SELECT current_hash FROM logs ORDER BY id DESC LIMIT 1")
		result = cursor.fetchone()
		prev_hash = result[0] if result else ""
		current_hash = hashlib.sha256(f"{prompt_enc}{response_enc}{prev_hash}".encode()).hexdigest()
		signature = self.private_key.sign(current_hash.encode()).hex()
		quorum_required, time_lock_until = self._policy_for_risk(risk_level)
		status = 'finalized' if quorum_required == 1 and time_lock_until is None else 'pending'
		cursor.execute(
			"""
			INSERT INTO logs (
				timestamp, user_id, prompt_encrypted, response_encrypted,
				previous_hash, current_hash, signature,
				risk_level, time_lock_until, quorum_required, status
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				datetime.now().isoformat(), user_id, prompt_enc, response_enc,
				prev_hash, current_hash, signature,
				risk_level.lower(), time_lock_until, quorum_required, status,
			)
		)
		log_id = cursor.lastrowid
		conn.commit()
		conn.close()
		return log_id

	def add_admin_signature(self, log_id: int, admin_username: str, admin_signature_hex: str) -> None:
		conn = sqlite3.connect("llm_logs.db")
		cursor = conn.cursor()
		cursor.execute("SELECT current_hash, risk_level, time_lock_until, quorum_required, status FROM logs WHERE id = ?", (log_id,))
		row = cursor.fetchone()
		if not row:
			conn.close()
			raise ValueError("log not found")
		current_hash, risk_level, time_lock_until, quorum_required, status = row
		cursor.execute(
			"""
			INSERT OR IGNORE INTO log_signatures (log_id, admin_username, admin_signature, signed_at)
			VALUES (?, ?, ?, ?)
			""",
			(log_id, admin_username, admin_signature_hex, datetime.now().isoformat()),
		)
		cursor.execute("SELECT COUNT(*) FROM log_signatures WHERE log_id = ?", (log_id,))
		count = cursor.fetchone()[0]
		time_ok = True
		if time_lock_until:
			try:
				time_ok = datetime.now() >= datetime.fromisoformat(time_lock_until)
			except Exception:
				time_ok = False
		if count >= int(quorum_required) and time_ok:
			cursor.execute("UPDATE logs SET status = 'finalized' WHERE id = ?", (log_id,))
		conn.commit()
		conn.close()

	def get_log_status(self, log_id: int) -> dict:
		conn = sqlite3.connect("llm_logs.db")
		cursor = conn.cursor()
		cursor.execute("SELECT id, risk_level, time_lock_until, quorum_required, status FROM logs WHERE id = ?", (log_id,))
		row = cursor.fetchone()
		if not row:
			conn.close()
			return {}
		cursor.execute("SELECT admin_username, signed_at FROM log_signatures WHERE log_id = ? ORDER BY signed_at", (log_id,))
		sigs = cursor.fetchall()
		conn.close()
		return {
			"log_id": row[0],
			"risk_level": row[1],
			"time_lock_until": row[2],
			"quorum_required": row[3],
			"status": row[4],
			"signatures": [{"admin": u, "signed_at": t} for (u, t) in sigs],
		}

	def verify_logs(self) -> bool:
		conn = sqlite3.connect("llm_logs.db")
		cursor = conn.cursor()
		cursor.execute("SELECT id, prompt_encrypted, response_encrypted, previous_hash, current_hash, signature, risk_level, time_lock_until, quorum_required, status FROM logs ORDER BY id")
		logs = cursor.fetchall()
		for i in range(len(logs)):
			id_, prompt_enc, response_enc, prev_hash, curr_hash, sig, risk_level, time_lock_until, quorum_required, status = logs[i]
			if i > 0:
				prev_curr_hash = logs[i-1][4]
				if prev_hash != prev_curr_hash:
					conn.close()
					return False
			expected_hash = hashlib.sha256(f"{prompt_enc}{response_enc}{prev_hash}".encode()).hexdigest()
			if curr_hash != expected_hash:
				conn.close()
				return False
			try:
				self.public_key.verify(bytes.fromhex(sig), curr_hash.encode())
			except Exception:
				conn.close()
				return False
			if status == 'finalized' and (risk_level or '').lower() in ('medium','high'):
				cursor.execute("SELECT COUNT(*) FROM log_signatures WHERE log_id = ?", (id_,))
				count = cursor.fetchone()[0]
				time_ok = True
				if time_lock_until:
					try:
						time_ok = datetime.now() >= datetime.fromisoformat(time_lock_until)
					except Exception:
						time_ok = False
				if not (count >= int(quorum_required) and time_ok):
					conn.close()
					return False
		conn.close()
		return True

	def _load_or_create_admin_keypair(self, admin_username: str) -> ed25519.Ed25519PrivateKey:
		os.makedirs('keys', exist_ok=True)
		priv_path = os.path.join('keys', f'admin_{admin_username}_ed25519_priv.bin')
		pub_path = os.path.join('keys', f'admin_{admin_username}_ed25519_pub.bin')
		if os.path.exists(priv_path):
			with open(priv_path, 'rb') as f:
				priv_bytes = f.read()
			return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
		# create new
		priv = ed25519.Ed25519PrivateKey.generate()
		pub = priv.public_key()
		priv_bytes = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
		pub_bytes = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
		with open(priv_path, 'wb') as f:
			f.write(priv_bytes)
		with open(pub_path, 'wb') as f:
			f.write(pub_bytes)
		return priv

	def sign_log_as_admin(self, log_id: int, admin_username: str) -> str:
		"""Server-side helper: sign the log's current_hash with admin's ed25519 key and store signature.
		Returns signature hex.
		"""
		conn = sqlite3.connect("llm_logs.db")
		cursor = conn.cursor()
		cursor.execute("SELECT current_hash FROM logs WHERE id = ?", (log_id,))
		row = cursor.fetchone()
		conn.close()
		if not row:
			raise ValueError("log not found")
		current_hash = row[0]
		priv = self._load_or_create_admin_keypair(admin_username)
		sig_hex = priv.sign(current_hash.encode()).hex()
		self.add_admin_signature(log_id, admin_username, sig_hex)
		return sig_hex
    