"""contributor-insights-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "contributor-insights-lifecycle"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateContributorInsights(ENABLE) moves a DISABLED table to ENABLED in
    DescribeContributorInsights and ListContributorInsights; DISABLE moves it back to DISABLED."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    baseline = ddb.describe_contributor_insights(TableName=t)
    assert baseline['ContributorInsightsStatus'] == 'DISABLED', (
        f"expected ContributorInsightsStatus=DISABLED before ENABLE, got {baseline!r}"
    )

    enable_resp = ddb.update_contributor_insights(TableName=t, ContributorInsightsAction='ENABLE')
    assert enable_resp['ContributorInsightsStatus'] in ('ENABLING', 'ENABLED'), (
        f"expected ContributorInsightsStatus in (ENABLING, ENABLED) from UpdateContributorInsights(ENABLE), got {enable_resp!r}"
    )

    enabled = _poll_until(
        lambda: ddb.describe_contributor_insights(TableName=t),
        lambda d: d.get('ContributorInsightsStatus') == 'ENABLED',
        timeout_s=60,
        interval_s=2.0,
        description='contributor insights ENABLED',
    )
    assert enabled['ContributorInsightsStatus'] == 'ENABLED', (
        f"expected ContributorInsightsStatus=ENABLED from DescribeContributorInsights, got {enabled!r}"
    )

    listed = _poll_until(
        lambda: ddb.list_contributor_insights(TableName=t)['ContributorInsightsSummaries'],
        lambda summaries: any(s['TableName'] == t for s in summaries),
        timeout_s=30,
        interval_s=2.0,
        description='table visible in ListContributorInsights',
    )
    assert any(s['TableName'] == t for s in listed), (
        f"expected table {t} present in ListContributorInsights summaries, got {listed!r}"
    )

    disable_resp = ddb.update_contributor_insights(TableName=t, ContributorInsightsAction='DISABLE')
    assert disable_resp['ContributorInsightsStatus'] in ('DISABLING', 'DISABLED'), (
        f"expected ContributorInsightsStatus in (DISABLING, DISABLED) from UpdateContributorInsights(DISABLE), got {disable_resp!r}"
    )

    disabled = _poll_until(
        lambda: ddb.describe_contributor_insights(TableName=t),
        lambda d: d.get('ContributorInsightsStatus') == 'DISABLED',
        timeout_s=60,
        interval_s=2.0,
        description='contributor insights DISABLED',
    )
    assert disabled['ContributorInsightsStatus'] == 'DISABLED', (
        f"expected ContributorInsightsStatus=DISABLED from DescribeContributorInsights after DISABLE, got {disabled!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
