"""contributor-insights-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "contributor-insights-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}')


def _wait_table_active(ddb, table_name, timeout_s=180, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)['Table']['TableStatus']
        if last == 'ACTIVE':
            return
        time.sleep(interval_s)
    raise AssertionError(f'table {table_name} never reached ACTIVE, last={last}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describe/List/UpdateContributorInsights return ResourceNotFoundException with AWS's exact
    message for a missing table; the same calls succeed on a real table, so the rejection is
    specific to the missing table."""
    ddb = ctx.client('dynamodb')
    missing = ctx.unique_name('sim2real-behav-no-such-table-')

    not_found_msg = f'Requested resource not found: Table: {missing} not found'

    describe_code, describe_msg = _error(lambda: ddb.describe_contributor_insights(TableName=missing))
    assert describe_code == 'ResourceNotFoundException', f'expected ResourceNotFoundException, got {describe_code}'
    assert describe_msg == not_found_msg, f'DescribeContributorInsights: expected {not_found_msg!r}, got {describe_msg!r}'

    list_code, list_msg = _error(lambda: ddb.list_contributor_insights(TableName=missing))
    assert list_code == 'ResourceNotFoundException', f'expected ResourceNotFoundException, got {list_code}'
    assert list_msg == not_found_msg, f'ListContributorInsights: expected {not_found_msg!r}, got {list_msg!r}'

    update_code, update_msg = _error(
        lambda: ddb.update_contributor_insights(TableName=missing, ContributorInsightsAction='ENABLE')
    )
    assert update_code == 'ResourceNotFoundException', f'expected ResourceNotFoundException, got {update_code}'
    assert update_msg == not_found_msg, f'UpdateContributorInsights: expected {not_found_msg!r}, got {update_msg!r}'

    # Positive control: the identical calls against a real table must succeed — otherwise
    # "rejects a nonexistent table" is indistinguishable from "rejects every call".
    table_name = ctx.unique_name('sim2real-behav-ci-table-')
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    described = ddb.describe_contributor_insights(TableName=table_name)
    assert described['ContributorInsightsStatus'] == 'DISABLED', (
        f'expected DISABLED by default, got {described["ContributorInsightsStatus"]}'
    )

    listed = ddb.list_contributor_insights(TableName=table_name)
    assert 'ContributorInsightsSummaries' in listed, f'expected a summaries list, got {listed!r}'

    updated = ddb.update_contributor_insights(TableName=table_name, ContributorInsightsAction='ENABLE')
    assert updated['ContributorInsightsStatus'] in ('ENABLING', 'ENABLED'), (
        f'expected ENABLING or ENABLED, got {updated["ContributorInsightsStatus"]}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
