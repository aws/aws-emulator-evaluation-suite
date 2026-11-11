"""list-settlement-records-empty-initial."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-settlement-records-empty-initial"
GROUP = "data-plane"
SERVICES = ["wafv2"]

_SCOPE = "CLOUDFRONT"


def _wafv2_cloudfront_client(ctx):
    """CLOUDFRONT-scope WAF operations are only accepted against the us-east-1
    endpoint, regardless of the configured region, so the client is pinned
    through ctx.client(..., region=)."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSettlementRecords filtered on a random RequestId returns no Settlements and no NextMarker, and
    a repeat of the same call returns the same empty result.
    """
    wafv2 = _wafv2_cloudfront_client(ctx)

    now = datetime.now(timezone.utc)
    time_window = {"StartTime": now - timedelta(hours=1), "EndTime": now}
    never_matched_request_id = str(uuid.uuid4())

    def _call():
        return wafv2.list_settlement_records(
            TimeWindow=time_window,
            Scope=_SCOPE,
            Currency="USDC",
            Filters=[{"Name": "RequestId", "Values": [never_matched_request_id]}],
        )

    try:
        resp1 = _call()
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "this account's automation role has no identity-based policy "
                "allowing wafv2:ListSettlementRecords -- CLOUDFRONT-scope WAF "
                "monetization/billing-settlement features are gated behind a "
                "separate grant this sandbox role doesn't hold"
            )
        raise
    assert resp1.get("Settlements", []) == [], (
        f"expected no settlements for a never-matched RequestId filter, got {resp1.get('Settlements')!r}"
    )
    assert not resp1.get("NextMarker"), (
        f"expected no NextMarker on an empty result, got {resp1.get('NextMarker')!r}"
    )

    resp2 = _call()
    assert resp2.get("Settlements", []) == [], (
        f"expected the identical empty result on a repeat call, got {resp2.get('Settlements')!r}"
    )
    assert not resp2.get("NextMarker"), (
        f"expected no NextMarker on the repeat call, got {resp2.get('NextMarker')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
