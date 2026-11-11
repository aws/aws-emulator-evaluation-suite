"""describe-endpoints."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-endpoints"
GROUP = 'limits'
SERVICES = ['dynamodb']


def _wait_table_deleted(ddb, name, timeout_s=90):
    import time
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=name)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return
            raise
        time.sleep(1.0)
    raise AssertionError(f'table {name} not deleted within {timeout_s}s')


def _get_endpoints(ddb):
    resp = ddb.describe_endpoints()
    endpoints = resp['Endpoints']
    assert len(endpoints) > 0, resp
    for e in endpoints:
        assert e['Address'], e
        assert isinstance(e['CachePeriodInMinutes'], int) and e['CachePeriodInMinutes'] > 0, e
    return endpoints


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEndpoints returns a non-empty list of endpoints, each with an address and a positive
    CachePeriodInMinutes, and the same addresses before, during and after a table's life.
    """
    ddb = ctx.client('dynamodb')

    before = _get_endpoints(ddb)

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

    during = _get_endpoints(ddb)

    ddb.delete_table(TableName=t)
    _wait_table_deleted(ddb, t)
    after = _get_endpoints(ddb)

    # The endpoint list is a SERVICE-level constant, not a resource's state: the
    # exact address set must be identical whether no table, one table, or a
    # just-deleted table exists in the account.
    before_addrs = sorted(e['Address'] for e in before)
    during_addrs = sorted(e['Address'] for e in during)
    after_addrs = sorted(e['Address'] for e in after)
    assert before_addrs == during_addrs == after_addrs, (
        f'endpoint addresses changed across table lifecycle: '
        f'before={before_addrs} during={during_addrs} after={after_addrs}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
