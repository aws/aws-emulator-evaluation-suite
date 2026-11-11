"""contributor-insights-enable-describe-list."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "contributor-insights-enable-describe-list"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateContributorInsights enabling status is reflected in DescribeContributorInsights
    and ListContributorInsights, and disabling it is reflected the same way."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ci-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )

    baseline = ddb.describe_contributor_insights(TableName=table_name)
    assert baseline["ContributorInsightsStatus"] == "DISABLED", (
        f"expected a freshly created table to start DISABLED, got {baseline['ContributorInsightsStatus']!r}"
    )

    enable_resp = ddb.update_contributor_insights(
        TableName=table_name, ContributorInsightsAction="ENABLE"
    )
    assert enable_resp["ContributorInsightsStatus"] in ("ENABLING", "ENABLED"), (
        f"expected ENABLING or ENABLED right after ENABLE, got {enable_resp['ContributorInsightsStatus']!r}"
    )

    described = _poll_until(
        lambda: ddb.describe_contributor_insights(TableName=table_name),
        lambda desc: desc["ContributorInsightsStatus"] == "ENABLED",
        timeout_s=120,
        interval_s=3,
    )
    assert described["ContributorInsightsStatus"] == "ENABLED", (
        f"expected DescribeContributorInsights to settle on ENABLED, got {described['ContributorInsightsStatus']!r}"
    )

    listed = _poll_until(
        lambda: _list_ci_status(ddb, table_name),
        lambda status: status == "ENABLED",
        timeout_s=60,
        interval_s=3,
    )
    assert listed == "ENABLED", (
        f"expected ListContributorInsights to report ENABLED for {table_name!r}, got {listed!r}"
    )

    disable_resp = ddb.update_contributor_insights(
        TableName=table_name, ContributorInsightsAction="DISABLE"
    )
    assert disable_resp["ContributorInsightsStatus"] in ("DISABLING", "DISABLED"), (
        f"expected DISABLING or DISABLED right after DISABLE, got {disable_resp['ContributorInsightsStatus']!r}"
    )

    described_off = _poll_until(
        lambda: ddb.describe_contributor_insights(TableName=table_name),
        lambda desc: desc["ContributorInsightsStatus"] == "DISABLED",
        timeout_s=120,
        interval_s=3,
    )
    assert described_off["ContributorInsightsStatus"] == "DISABLED", (
        f"expected DescribeContributorInsights to settle on DISABLED, got {described_off['ContributorInsightsStatus']!r}"
    )

    listed_off = _poll_until(
        lambda: _list_ci_status(ddb, table_name),
        lambda status: status is None,
        timeout_s=60,
        interval_s=3,
    )
    assert listed_off is None, (
        f"expected {table_name!r} to drop out of ListContributorInsights once DISABLED, "
        f"still reported as {listed_off!r}"
    )


def _list_ci_status(ddb: Any, table_name: str) -> str | None:
    resp = ddb.list_contributor_insights(TableName=table_name)
    for summary in resp.get("ContributorInsightsSummaries", []):
        if summary["TableName"] == table_name and summary.get("IndexName") is None:
            return summary["ContributorInsightsStatus"]
    for summary in resp.get("ContributorInsightsSummaries", []):
        if summary["TableName"] == table_name:
            return summary["ContributorInsightsStatus"]
    return None


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
