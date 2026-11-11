"""update-account-settings-out-of-range-rejected."""
from __future__ import annotations

import re
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "update-account-settings-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:opensearchserverless-account-settings")
def run(ctx) -> None:
    """UpdateAccountSettings above the fixed 1,700 OCU account-wide indexing ceiling (a value botocore's
    min=2 check lets through) is rejected by the service with ServiceQuotaExceededException and leaves
    the settings unchanged, while an in-range update succeeds (positive control)."""
    aoss = ctx.client("opensearchserverless")

    original = aoss.get_account_settings()["accountSettingsDetail"].get("capacityLimits")

    def _restore() -> None:
        if original:
            aoss.update_account_settings(capacityLimits=original)

    ctx.on_cleanup(_restore)

    # negative: 1,701 OCU exceeds the documented, non-adjustable 1,700 OCU account-wide
    # maximum. It is >= botocore's client-side min=2, so the request reaches the wire, and
    # the service rejects it with ServiceQuotaExceededException (not
    # ValidationException, which is what the generic "out of range" shape would predict)
    # -- the account is left untouched.
    code, message = _error_code(
        lambda: aoss.update_account_settings(
            capacityLimits={"maxIndexingCapacityInOCU": 1701, "maxSearchCapacityInOCU": 4}
        )
    )
    # The message reports the account-wide OCU totals, which sum the capacity of every collection
    # group in the account, including ones other runs create and delete concurrently: the totals
    # are read from the message, and the sentence around them, with the new total as the request
    # plus the collection groups' capacity in both places, is asserted exactly.
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code!r}"
    totals = re.search(
        r"Current settings: ([0-9.]+) OCUs for collections that are not part of any collection group, "
        r"([0-9.]+) OCUs for collection groups\.",
        message or "",
    )
    assert totals, f"expected the quota refusal to report the current settings, got {message!r}"
    ungrouped, grouped = totals.group(1), totals.group(2)
    total = 1701 + float(grouped)
    expected = (
        f"The requested total indexing capacity of {total} OCUs exceeds your maximum indexing capacity "
        f"service quota limit of 1700 OCUs. Current settings: {ungrouped} OCUs for collections that "
        f"are not part of any collection group, {grouped} OCUs for collection groups. New request of "
        f"1701 OCUs would bring total to {total} OCUs."
    )
    assert message == expected, (
        f"expected the exact ServiceQuotaExceededException message AWS returns, got {message!r}"
    )

    # effect absent: the account settings were not silently clamped down to 1,700 (or anything else)
    unchanged = aoss.get_account_settings()["accountSettingsDetail"].get("capacityLimits")
    assert unchanged == original, f"expected unchanged capacityLimits {original!r}, got {unchanged!r}"

    # positive control: an in-range value is accepted
    accepted_limits = {"maxIndexingCapacityInOCU": 4, "maxSearchCapacityInOCU": 4}
    aoss.update_account_settings(capacityLimits=accepted_limits)
    now = aoss.get_account_settings()["accountSettingsDetail"]["capacityLimits"]
    assert now["maxIndexingCapacityInOCU"] == 4, f"expected maxIndexingCapacityInOCU=4, got {now!r}"
    assert now["maxSearchCapacityInOCU"] == 4, f"expected maxSearchCapacityInOCU=4, got {now!r}"


# ===== self-contained helpers =====
def _error_code(fn: Callable[[], Any]) -> tuple:
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
