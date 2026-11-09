"""Remediation Engine for SecretShield."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from secretshield.config import ShieldConfig
from secretshield.scanner.base import Finding
from secretshield.vault.base import BaseVaultProvider, VaultResult


@dataclass
class RemediationPlan:
    """Plan specifying how a detected secret will be replaced in code."""

    finding: Finding
    vault_result: Optional[VaultResult]
    file_path: Path
    line_number: int
    original_line: str
    proposed_line: str
    env_var_name: str
    replacement_token: str
    success: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "rule_id": self.finding.rule_id,
            "env_var_name": self.env_var_name,
            "original_line": self.original_line,
            "proposed_line": self.proposed_line,
            "replacement_token": self.replacement_token,
            "success": self.success,
            "error": self.error,
            "vault_result": self.vault_result.to_dict() if self.vault_result else None,
        }


def derive_env_var_name(finding: Finding) -> str:
    """Determine an appropriate UPPER_SNAKE_CASE environment variable name."""
    raw_name = finding.hint or finding.rule_id
    if not raw_name or raw_name.lower() in ("secret", "token", "key", "generic_secret", "generic_api_key"):
        # Derive from filename
        stem = Path(finding.file_path).stem.upper()
        raw_name = f"{stem}_SECRET"

    clean = re.sub(r"[^a-zA-Z0-9_]+", "_", raw_name)
    clean = re.sub(r"_+", "_", clean).strip("_").upper()
    if clean and clean[0].isdigit():
        clean = f"SECRET_{clean}"
    return clean or "APP_SECRET"


def generate_syntax_replacement(
    file_path: str,
    raw_secret: str,
    env_var_name: str,
    original_line: str,
    vault_result: Optional[VaultResult] = None,
    use_vault_uri: bool = False,
) -> Tuple[str, str]:
    """
    Generate language/syntax-specific replacement for the secret.
    Returns (replacement_token, proposed_line).
    """
    ext = Path(file_path).suffix.lower()
    filename = Path(file_path).name.lower()

    # Determine token value
    if use_vault_uri and vault_result and vault_result.reference_uri:
        token = vault_result.reference_uri
    else:
        token = env_var_name

    # 1. Dotenv files (.env, .env.local, .env.example)
    if filename.startswith(".env") or ext in (".env",):
        # In .env files, usually replace with reference or comment out
        if original_line.strip().startswith(f"{env_var_name}="):
            proposed = f"{env_var_name}=  # Migrated by SecretShield to {vault_result.reference_uri if vault_result else env_var_name}"
            return token, proposed
        replacement = f"${{{token}}}"
        proposed = original_line.replace(raw_secret, replacement)
        return replacement, proposed

    # 2. YAML (.yaml, .yml)
    if ext in (".yaml", ".yml"):
        replacement = f"${{{token}}}"
        # If secret was unquoted in yaml, keep it clean; if quoted, keep quotes
        proposed = original_line.replace(raw_secret, replacement)
        return replacement, proposed

    # 3. JSON (.json)
    if ext in (".json",):
        replacement = f"${{{token}}}"
        proposed = original_line.replace(raw_secret, replacement)
        return replacement, proposed

    # 4. JavaScript / TypeScript (.js, .jsx, .ts, .tsx, .mjs, .cjs)
    if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        # Check if secret is inside quotes: "raw_secret" or 'raw_secret' or `raw_secret`
        pattern_double = f'"{raw_secret}"'
        pattern_single = f"'{raw_secret}'"
        pattern_tick = f"`{raw_secret}`"

        code_expr = f"process.env.{env_var_name}"
        if pattern_double in original_line:
            proposed = original_line.replace(pattern_double, code_expr)
            return code_expr, proposed
        elif pattern_single in original_line:
            proposed = original_line.replace(pattern_single, code_expr)
            return code_expr, proposed
        elif pattern_tick in original_line:
            proposed = original_line.replace(pattern_tick, code_expr)
            return code_expr, proposed
        else:
            proposed = original_line.replace(raw_secret, code_expr)
            return code_expr, proposed

    # 5. Python (.py)
    if ext in (".py",):
        pattern_double = f'"{raw_secret}"'
        pattern_single = f"'{raw_secret}'"
        code_expr = f'os.getenv("{env_var_name}", "")'

        if pattern_double in original_line:
            proposed = original_line.replace(pattern_double, code_expr)
            return code_expr, proposed
        elif pattern_single in original_line:
            proposed = original_line.replace(pattern_single, code_expr)
            return code_expr, proposed
        else:
            proposed = original_line.replace(raw_secret, code_expr)
            return code_expr, proposed

    # 6. Go (.go)
    if ext in (".go",):
        pattern_double = f'"{raw_secret}"'
        code_expr = f'os.Getenv("{env_var_name}")'
        if pattern_double in original_line:
            proposed = original_line.replace(pattern_double, code_expr)
            return code_expr, proposed
        else:
            proposed = original_line.replace(raw_secret, code_expr)
            return code_expr, proposed

    # 7. Shell / Bash (.sh, .bash, .zsh)
    if ext in (".sh", ".bash", ".zsh"):
        replacement = f'"${{{env_var_name}:-}}"'
        pattern_double = f'"{raw_secret}"'
        pattern_single = f"'{raw_secret}'"
        if pattern_double in original_line:
            proposed = original_line.replace(pattern_double, replacement)
            return replacement, proposed
        elif pattern_single in original_line:
            proposed = original_line.replace(pattern_single, replacement)
            return replacement, proposed
        else:
            proposed = original_line.replace(raw_secret, f"${{{env_var_name}}}")
            return f"${{{env_var_name}}}", proposed

    # Default fallback: replace secret with ${ENV_VAR_NAME}
    replacement = f"${{{token}}}"
    proposed = original_line.replace(raw_secret, replacement)
    return replacement, proposed


def create_remediation_plan(
    finding: Finding,
    vault_result: Optional[VaultResult] = None,
    use_vault_uri: bool = False,
    custom_env_var: Optional[str] = None,
    repo_root: Optional[Path] = None,
) -> RemediationPlan:
    """Create a structured RemediationPlan for a single finding."""
    root = repo_root or Path.cwd()
    full_path = root / finding.file_path

    env_var = custom_env_var or (vault_result.env_var_name if vault_result else derive_env_var_name(finding))
    token, proposed_line = generate_syntax_replacement(
        file_path=finding.file_path,
        raw_secret=finding.secret_raw,
        env_var_name=env_var,
        original_line=finding.line_content,
        vault_result=vault_result,
        use_vault_uri=use_vault_uri,
    )

    return RemediationPlan(
        finding=finding,
        vault_result=vault_result,
        file_path=full_path,
        line_number=finding.line_number,
        original_line=finding.line_content,
        proposed_line=proposed_line,
        env_var_name=env_var,
        replacement_token=token,
    )


def apply_remediation_plan(plan: RemediationPlan) -> Tuple[bool, Optional[str]]:
    """Safely apply the planned line replacement to the target file on disk."""
    if not plan.file_path.exists():
        err = f"File not found: {plan.file_path}"
        plan.error = err
        plan.success = False
        return False, err

    try:
        content = plan.file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines(keepends=True)

        if plan.line_number < 1 or plan.line_number > len(lines):
            err = f"Line number {plan.line_number} out of range in {plan.file_path} (total lines: {len(lines)})"
            plan.error = err
            plan.success = False
            return False, err

        target_idx = plan.line_number - 1
        curr_line = lines[target_idx]

        # Verify raw secret or original line is still present
        if plan.finding.secret_raw not in curr_line:
            # Check if secret was already replaced or line modified
            err = f"Secret no longer present at line {plan.line_number} in {plan.file_path}"
            plan.error = err
            plan.success = False
            return False, err

        # Preserve line ending
        ending = ""
        if curr_line.endswith("\r\n"):
            ending = "\r\n"
        elif curr_line.endswith("\n"):
            ending = "\n"

        clean_proposed = plan.proposed_line.rstrip("\r\n") + ending
        lines[target_idx] = clean_proposed

        plan.file_path.write_text("".join(lines), encoding="utf-8")
        plan.success = True
        return True, None
    except Exception as e:
        err = f"Failed to rewrite file {plan.file_path}: {e}"
        plan.error = err
        plan.success = False
        return False, err
