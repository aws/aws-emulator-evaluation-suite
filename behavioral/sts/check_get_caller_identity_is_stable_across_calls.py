"""get-caller-identity-is-stable-across-calls."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-caller-identity-is-stable-across-calls"
GROUP = 'credential-issuance'
SERVICES = ['sts']

@tags("axis:happy-path", "cap:unclassified", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCallerIdentity is a pure read: repeated calls must return identical identity."""

    sts = ctx.client("sts")

    calls = [sts.get_caller_identity() for _ in range(3)]
    first = calls[0]
    for i, later in enumerate(calls[1:], start=2):
        for field in ("Account", "Arn", "UserId"):
            assert first[field] == later[field], (
                f"{field} changed between call 1 and call {i}: {first[field]} vs {later[field]}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
