"""get-sampling-targets-reservoir-ttl-honored."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "get-sampling-targets-reservoir-ttl-honored"
GROUP = "visibility-timeout-ttl"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSamplingTargets returns a ReservoirQuotaTTL (and refresh Interval) that governs
    how long a client may reuse the allocated reservoir quota before it must call
    GetSamplingTargets again, rather than an already-expired or absent TTL."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": 1000,
            "FixedRate": 0.05,
            "ReservoirSize": 10,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        },
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=rule_name))

    # AWS documents that "the response ... might not include a quota the first time you
    # call it" — a client must keep reporting statistics (borrowing one trace/sec in the
    # meantime) until X-Ray allocates a reservoir quota with a TTL. Poll a bounded number
    # of times, spaced far enough apart to fall in distinct ~10s statistics windows.
    client_id = uuid.uuid4().hex[:24]
    target = None
    before_call = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and target is None:
        before_call = datetime.now(timezone.utc)
        resp = xray.get_sampling_targets(
            SamplingStatisticsDocuments=[
                {
                    "RuleName": rule_name,
                    "ClientID": client_id,
                    "Timestamp": before_call,
                    "RequestCount": 100,
                    "SampledCount": 5,
                    "BorrowCount": 1,
                }
            ]
        )
        assert not resp.get("UnprocessedStatistics"), resp.get("UnprocessedStatistics")
        targets = resp["SamplingTargetDocuments"]
        matching = [t for t in targets if t.get("RuleName") == rule_name]
        assert len(matching) == 1, f"expected exactly one target document, got {targets}"
        candidate = matching[0]
        if candidate.get("ReservoirQuotaTTL") is not None:
            target = candidate
        else:
            time.sleep(2)

    assert target is not None, (
        "GetSamplingTargets never allocated a ReservoirQuotaTTL for a rule with a "
        "non-zero reservoir after repeated statistics reporting"
    )
    ttl = target["ReservoirQuotaTTL"]
    assert ttl > before_call, "ReservoirQuotaTTL must lie in the future when first allocated"
    # Measured against real AWS: the window is a short refresh cycle (~5 minutes), not a
    # far-future/permanent value. A looser bound cannot tell "honored" apart from "never expires".
    window_s = (ttl - before_call).total_seconds()
    assert 0 < window_s <= 300, (
        f"ReservoirQuotaTTL window is {window_s}s, expected a short bounded refresh "
        f"window (<=300s), not a far-future/permanent value"
    )

    interval = target.get("Interval")
    if interval is not None:
        assert interval > 0, f"expected a positive refresh Interval, got {interval}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
