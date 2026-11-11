"""describe-attack-unknown-id-no-fabricated-detail."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "describe-attack-unknown-id-no-fabricated-detail"
GROUP = "overly-permissive"
SERVICES = ["shield"]

_DETAIL_FIELDS = (
    "ResourceArn",
    "StartTime",
    "EndTime",
    "AttackCounters",
    "AttackProperties",
    "Mitigations",
    "SubResources",
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAttack for a well-formed but unknown AttackId returns no Attack key and no populated detail
    field, while ListAttacks succeeds, so an emulator that invents attack details for an arbitrary id fails.
    """
    shield = ctx.client("shield")

    now = datetime.now(timezone.utc)
    window = {"FromInclusive": now - timedelta(days=1), "ToExclusive": now}
    control = shield.list_attacks(StartTime=window, EndTime=window)
    assert isinstance(control.get("AttackSummaries"), list), (
        f"positive control failed: ListAttacks did not return a summaries list, got {control!r}"
    )

    bogus_attack_id = "ff" * 18  # well-formed (hex, within 1-128 length, matches pattern) but unknown
    resp = shield.describe_attack(AttackId=bogus_attack_id)
    resp.pop("ResponseMetadata", None)
    assert "Attack" not in resp, f"expected no Attack key for an unknown AttackId, got {resp!r}"
    attack = resp.get("Attack") or {}
    populated = {field: attack[field] for field in _DETAIL_FIELDS if attack.get(field)}
    assert not populated, (
        f"expected no fabricated attack detail for an unknown AttackId, got {populated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
