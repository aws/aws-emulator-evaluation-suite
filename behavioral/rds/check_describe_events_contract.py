"""describe-events-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-events-contract"
GROUP = 'events'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEvents: the account-wide event stream is always describable over a bounded recent
    Duration, with no source needing to exist. Overly-permissive boundary: a MaxRecords below the
    documented 20-100 range must be rejected rather than silently clamped.
    """
    rds = ctx.client("rds")
    resp = rds.describe_events(Duration=60)
    assert "Events" in resp, f"DescribeEvents response missing Events key: {resp!r}"
    assert isinstance(resp["Events"], list), f"Events is not a list: {resp['Events']!r}"

    resp2 = rds.describe_events(SourceType="db-instance", Duration=1440)
    assert isinstance(resp2.get("Events"), list), (
        f"Events is not a list for SourceType=db-instance: {resp2.get('Events')!r}"
    )

    err = _rejection(lambda: rds.describe_events(MaxRecords=5))
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected the service to reject MaxRecords below the documented 20-100 range with "
        f"InvalidParameterValue, got: {err}"
    )
    assert err.get("Message") == "Invalid value 5 for MaxRecords. Must be between 20 and 100", (
        f"unexpected InvalidParameterValue message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
