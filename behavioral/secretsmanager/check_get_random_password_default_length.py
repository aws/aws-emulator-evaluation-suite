"""get-random-password-default-length."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-random-password-default-length"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:unclassified", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRandomPassword defaults to a 32-character password when no length is given."""
    sm = ctx.client("secretsmanager")
    resp = sm.get_random_password()
    pwd = resp["RandomPassword"]
    assert len(pwd) == 32, f"GetRandomPassword with no PasswordLength must default to 32 characters, got {len(pwd)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
