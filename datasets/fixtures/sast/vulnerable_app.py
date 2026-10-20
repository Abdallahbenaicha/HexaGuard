"""SecuraX Evaluation Lab — Authored SAST Benchmark Fixture.

Target ID: fixture_sast_python
Engine Tested: Bandit v1.8.3
Dataset: hexaguard_bench_core v1.0.0 (split: dev)
License: MIT
Author: SecuraX Security Research Team

This fixture contains:
  1. Vulnerabilities detectable by Bandit (B602 shell=True, B324 weak MD5).
  2. Real vulnerabilities undetectable by Bandit's AST rules (CWE-22 Path Traversal, CWE-79 unescaped template).
  3. Explicit Negative Controls (Safe look-alikes that must NOT trigger alerts).
"""

import ast
import hashlib
import os
import secrets
import subprocess


# ── VULNERABLE CASES (In-scope for SAST) ──────────────────────────────────────

def vuln_command_exec(user_cmd: str) -> None:
    """Case: CASE-SAST-CMDI-001 | CWE-78 (OS Command Injection)
    Bandit detects via B602 (subprocess_popen_with_shell_equals_true).
    """
    subprocess.Popen(user_cmd, shell=True)


def vuln_weak_crypto() -> str:
    """Case: CASE-SAST-CRYPTO-001 | CWE-327 (Broken Crypto / Weak Hash)
    Bandit detects via B324 (hashlib_new_insecure_functions).
    """
    return hashlib.md5(b"password123").hexdigest()


def vuln_path_traversal(user_filename: str) -> str:
    """Case: CASE-SAST-TRAVERSAL-001 | CWE-22 (Path Traversal)
    Bandit misses this: AST rules do not track dataflow into open() -> FALSE NEGATIVE.
    """
    with open("/data/storage/" + user_filename, "r") as f:
        return f.read()


def vuln_unescaped_xss(user_input: str) -> str:
    """Case: CASE-SAST-XSS-001 | CWE-79 (Cross-Site Scripting / Template Injection)
    Bandit misses this: AST rules do not perform HTML taint tracking -> FALSE NEGATIVE.
    """
    template = f"<html><body>User feedback: {user_input}</body></html>"
    return template


# ── NEGATIVE CONTROLS (Safe Look-alikes — Must NOT trigger alerts) ─────────────

def safe_eval_control(expression: str):
    """Case: CASE-SAST-EVAL-002-NEG | CWE-94 Negative Control
    Safe literal parsing with ast.literal_eval().
    """
    return ast.literal_eval(expression)


def safe_hash_control(data: bytes) -> str:
    """Case: CASE-SAST-CRYPTO-002-NEG | CWE-327 Negative Control
    Cryptographically secure hash with SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def safe_random_control() -> str:
    """Case: CASE-SAST-RAND-002-NEG | CWE-330 Negative Control
    CSPRNG token generation using secrets module.
    """
    return secrets.token_hex(32)


def safe_file_control(user_filename: str) -> str:
    """Case: CASE-SAST-TRAVERSAL-002-NEG | CWE-22 Negative Control
    Safe file reading using os.path.basename path containment.
    """
    safe_name = os.path.basename(user_filename)
    safe_path = os.path.join("/data/storage", safe_name)
    with open(safe_path, "r") as f:
        return f.read()
