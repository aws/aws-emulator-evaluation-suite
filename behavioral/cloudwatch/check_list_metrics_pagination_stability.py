"""list-metrics-pagination-stability."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-metrics-pagination-stability"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics returns a stable, non-duplicating ordering of metrics across
    paginated calls with the same filter."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-listmetrics-")
    n = 8
    metric_names = [f"probe-metric-{i}" for i in range(n)]
    now = datetime.datetime.utcnow()
    for mname in metric_names:
        cw.put_metric_data(
            Namespace=ns,
            MetricData=[{"MetricName": mname, "Timestamp": now, "Value": 1.0}],
        )

    def list_all():
        names = []
        paginator = cw.get_paginator("list_metrics")
        for page in paginator.paginate(Namespace=ns):
            for m in page.get("Metrics", []):
                names.append(m["MetricName"])
        return names

    first = _poll_until(
        list_all, lambda names: len(names) >= n, timeout_s=120, interval_s=5,
        description="all published metrics become visible via ListMetrics",
    )
    assert len(first) == len(set(first)), f"ListMetrics returned duplicates within one traversal: {first}"
    assert set(first) == set(metric_names), (
        f"expected exactly {set(metric_names)}, got {set(first)}"
    )

    # A second, independent paginated traversal with the identical filter must
    # produce the exact same ordered sequence -- the stability guarantee.
    second = list_all()
    assert second == first, (
        f"ListMetrics ordering must be stable across separate calls with the same filter; "
        f"first={first} second={second}"
    )

    # Positive control: a valid RecentlyActive value is accepted, so the rejection asserted
    # below is specific to the invalid enum value -- not a symptom of RecentlyActive being
    # broken outright for this namespace/account.
    cw.list_metrics(Namespace=ns, RecentlyActive="PT3H")

    # Overly-permissive check: RecentlyActive only accepts the literal "PT3H" per the API
    # model; any other value must be rejected by the service with a specific error code, not
    # silently ignored/treated as "no filter". A ParamValidationError (raised locally by
    # botocore before the request is even sent) does not count as this rejection.
    try:
        cw.list_metrics(Namespace=ns, RecentlyActive="NotAValidValue")
        raise AssertionError(
            "an invalid RecentlyActive value must be rejected, but the call succeeded"
        )
    except ClientError as exc:
        err_code = exc.response["Error"]["Code"]
        assert err_code == "InvalidParameterValue", (
            f"expected InvalidParameterValue, got {err_code}"
        )
        err_message = exc.response["Error"].get("Message")
        assert err_message == 'Request parameter recentlyActive value is invalid', f"unexpected message: {err_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
