"""numeric-precision-ocu-capacity-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "numeric-precision-ocu-capacity-preserved"
GROUP = "server-side"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:opensearchserverless-account-settings")
def run(ctx) -> None:
    """Numeric OCU capacity values set via UpdateAccountSettings come back from
    GetAccountSettings with the exact integer values submitted -- no rounding
    to a power of two, no truncation, no float drift."""
    osc = ctx.client("opensearchserverless")

    original = osc.get_account_settings()["accountSettingsDetail"].get("capacityLimits")

    def _restore():
        if original:
            osc.update_account_settings(capacityLimits=original)

    ctx.on_cleanup(_restore)

    # Deliberately odd, non-power-of-two values to catch silent rounding.
    indexing_ocu = 7
    search_ocu = 13
    osc.update_account_settings(
        capacityLimits={"maxIndexingCapacityInOCU": indexing_ocu, "maxSearchCapacityInOCU": search_ocu}
    )

    fetched = osc.get_account_settings()["accountSettingsDetail"]["capacityLimits"]
    assert fetched["maxIndexingCapacityInOCU"] == indexing_ocu, (
        f"expected maxIndexingCapacityInOCU={indexing_ocu}, got {fetched['maxIndexingCapacityInOCU']!r}"
    )
    assert fetched["maxSearchCapacityInOCU"] == search_ocu, (
        f"expected maxSearchCapacityInOCU={search_ocu}, got {fetched['maxSearchCapacityInOCU']!r}"
    )
    assert isinstance(fetched["maxIndexingCapacityInOCU"], int), (
        f"expected an exact integer, got {type(fetched['maxIndexingCapacityInOCU'])}"
    )
    assert isinstance(fetched["maxSearchCapacityInOCU"], int), (
        f"expected an exact integer, got {type(fetched['maxSearchCapacityInOCU'])}"
    )

    # Restore immediately rather than waiting for teardown, to minimize the
    # window during which this account-wide setting is altered.
    _restore()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
