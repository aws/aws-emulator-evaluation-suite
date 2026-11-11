"""re-enabling-a-stream-mints-a-new-descriptor."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "re-enabling-a-stream-mints-a-new-descriptor"
GROUP = 'streams'
SERVICES = ['dynamodb']


def _wait_active(ddb, table, deadline_s=240):
    """Poll DescribeTable until the table is ACTIVE with no index still mutating."""
    import time

    end = time.time() + deadline_s
    while time.time() < end:
        t = ddb.describe_table(TableName=table)['Table']
        busy = [i for i in t.get('GlobalSecondaryIndexes') or []
                if i.get('IndexStatus') != 'ACTIVE']
        if t['TableStatus'] == 'ACTIVE' and not busy:
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never settled to ACTIVE within {deadline_s}s')


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Disabling and re-enabling a stream does not resume the old one: DynamoDB creates a NEW stream
    with a different descriptor, so a consumer holding the old ARN is reading a dead stream."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST',
                     StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_IMAGE'})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    first = ddb.describe_table(TableName=table)['Table']['LatestStreamArn']
    ddb.update_table(TableName=table, StreamSpecification={'StreamEnabled': False})
    _wait_active(ddb, table)
    ddb.update_table(TableName=table,
                     StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_IMAGE'})
    t = _wait_active(ddb, table)
    second = t['LatestStreamArn']
    assert second and second != first, (
        f're-enabling must mint a new stream descriptor, got the same one: {second}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
