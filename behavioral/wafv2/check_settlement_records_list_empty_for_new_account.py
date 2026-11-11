"""settlement-records-list-empty-for-new-account."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "settlement-records-list-empty-for-new-account"
GROUP = "data-plane"
SERVICES = ["wafv2"]


def _cloudfront_wafv2_client(ctx):
    """CLOUDFRONT-scope WAFv2 operations are only valid against the us-east-1
    endpoint regardless of the runner's configured region, so the client is
    pinned there on every target."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSettlementRecords (CLOUDFRONT scope, USDC) for an account with no settlement activity returns
    an empty Settlements list and no NextMarker, and a second read returns the same empty list.
    """
    wafv2 = _cloudfront_wafv2_client(ctx)
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=24)

    try:
        resp = wafv2.list_settlement_records(
            TimeWindow={"StartTime": start, "EndTime": end},
            Scope="CLOUDFRONT",
            Currency="USDC",
        )
    except Exception as exc:  # pragma: no cover - account not enrolled in monetization
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
        if code in ("WAFNonexistentItemException", "WAFInvalidOperationException"):
            raise AssertionError(
                f"ListSettlementRecords returned {code}; this account has no AI bot "
                "monetization enrollment, which is not provisionable through any "
                "WAFv2 API"
            ) from exc
        raise
    assert "Settlements" in resp, f"ListSettlementRecords response missing Settlements key: {resp}"
    assert isinstance(resp["Settlements"], list), (
        f"expected Settlements to be a list, got {type(resp['Settlements'])}: {resp['Settlements']!r}"
    )
    assert resp["Settlements"] == [], (
        f"expected no settlement records for a fresh account, got {resp['Settlements']}"
    )
    assert not resp.get("NextMarker"), (
        f"expected no NextMarker on an empty settlement result, got {resp.get('NextMarker')!r}"
    )

    resp2 = wafv2.list_settlement_records(
        TimeWindow={"StartTime": start, "EndTime": end},
        Scope="CLOUDFRONT",
        Currency="USDC",
    )
    assert resp2["Settlements"] == resp["Settlements"] == [], (
        f"expected a second, independent read to return the identical empty result, "
        f"got {resp['Settlements']} then {resp2['Settlements']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
