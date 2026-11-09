"""Auto-Remediation and Interactive agent module for SecretShield."""

from secretshield.remediation.engine import (
    RemediationPlan,
    apply_remediation_plan,
    create_remediation_plan,
    derive_env_var_name,
    generate_syntax_replacement,
)
from secretshield.remediation.interactive import (
    run_interactive_remediation,
)

__all__ = [
    "RemediationPlan",
    "apply_remediation_plan",
    "create_remediation_plan",
    "derive_env_var_name",
    "generate_syntax_replacement",
    "run_interactive_remediation",
]
