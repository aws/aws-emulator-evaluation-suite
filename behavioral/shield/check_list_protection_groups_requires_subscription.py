"""list-protection-groups-requires-subscription."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-protection-groups-requires-subscription"
GROUP = "error-semantics"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListProtectionGroups on an account without a Shield Advanced subscription raises
    ResourceNotFoundException "The subscription does not exist." rather than an empty list, while ListAttacks
    succeeds with no attacks.
    """
    shield = ctx.client("shield")

    start = datetime(2000, 1, 1, tzinfo=timezone.utc)
    end = datetime(2000, 1, 2, tzinfo=timezone.utc)
    control = shield.list_attacks(
        StartTime={"FromInclusive": start, "ToExclusive": end},
        EndTime={"FromInclusive": start, "ToExclusive": end},
    )
    assert control["AttackSummaries"] == [], (
        f"positive control: expected ListAttacks to succeed with no attacks, "
        f"got {control['AttackSummaries']!r}"
    )

    error = _client_error(lambda: shield.list_protection_groups())
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "The subscription does not exist.", (
        f"expected a subscription-not-found message, got {error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects ListProtectionGroups without a subscription, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
