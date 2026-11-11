"""aggregator-sources-status."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")

CHECK = "aggregator-sources-status"
GROUP = 'aggregator'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationAggregatorSourcesStatus reports a well-formed ACCOUNT-sourced status for a new
    aggregator; the list fills asynchronously, so the check polls for the entry to appear.
    An unknown aggregator name is rejected with NoSuchConfigurationAggregatorException."""
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cfg-aggregator-")
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AwsRegions": [ctx.region]}
        ],
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda a=name: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=a))

    statuses = _poll_until(
        lambda: cfg.describe_configuration_aggregator_sources_status(
            ConfigurationAggregatorName=name
        ).get("AggregatedSourceStatusList", []),
        lambda s: len(s) >= 1
        and all(e.get("LastUpdateStatus") in ("SUCCEEDED", "FAILED") for e in s),
        timeout_s=max(1.0, min(500.0, (ctx.time_left() or 500.0) - 5)),
        interval_s=15,
        description="aggregated source status entry with a terminal LastUpdateStatus for the just-created ACCOUNT source",
    )
    assert len(statuses) == 1, (
        f"expected exactly one status entry (one AccountAggregationSources with one "
        f"account/region was configured): {statuses}"
    )
    s = statuses[0]
    assert s.get("SourceType") == "ACCOUNT", f"expected SourceType=ACCOUNT: {s}"
    assert s.get("SourceId") == account_id, f"expected SourceId={account_id!r}: {s}"
    assert s.get("AwsRegion") == ctx.region, f"expected AwsRegion={ctx.region!r}: {s}"
    assert s.get("LastUpdateStatus") == "SUCCEEDED", (
        f"expected LastUpdateStatus=SUCCEEDED for the caller's own account/region source, "
        f"got {s.get('LastUpdateStatus')!r}: {s}"
    )

    # An unknown aggregator name must be rejected, not answered with an
    # empty status list.
    err = _client_error(
        lambda: cfg.describe_configuration_aggregator_sources_status(
            ConfigurationAggregatorName=ctx.unique_name("sim2real-behav-cfg-absent-agg-")
        )
    )
    assert err.get("Code") == "NoSuchConfigurationAggregatorException", err
    assert err.get("Message") == (
        "The configuration aggregator does not exist. Check the configuration "
        "aggregator name and try again."
    ), err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
