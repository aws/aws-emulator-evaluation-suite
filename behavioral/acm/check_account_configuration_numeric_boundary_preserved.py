"""account-configuration-numeric-boundary-preserved."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "account-configuration-numeric-boundary-preserved"
GROUP = "representation"
SERVICES = ["acm"]

_DEFAULT_DAYS_BEFORE_EXPIRY = 45  # AWS's documented default for ExpiryEvents.DaysBeforeExpiry


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:acm-account-configuration")
def run(ctx) -> None:
    """PutAccountConfiguration with the minimum allowed ExpiryEvents.DaysBeforeExpiry (the
    field has range min=1) round-trips through GetAccountConfiguration with exact numeric
    precision -- no rounding, truncation, or snapping back to the default."""
    acm = ctx.client("acm")

    acm.put_account_configuration(ExpiryEvents={"DaysBeforeExpiry": 1}, IdempotencyToken=uuid.uuid4().hex)
    ctx.on_cleanup(
        lambda: acm.put_account_configuration(
            ExpiryEvents={"DaysBeforeExpiry": _DEFAULT_DAYS_BEFORE_EXPIRY},
            IdempotencyToken=uuid.uuid4().hex,
        )
    )

    days = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    assert days == 1, f"expected DaysBeforeExpiry to round-trip as exactly 1, got {days!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
