"""describe-limits."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-limits"
GROUP = 'limits'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLimits reports positive account and table capacity limits with TableMax* <=
    AccountMax*, and the account-level ceiling is unchanged after creating a provisioned table."""
    ddb = ctx.client('dynamodb')
    limits1 = ddb.describe_limits()
    for key in (
        'AccountMaxReadCapacityUnits',
        'AccountMaxWriteCapacityUnits',
        'TableMaxReadCapacityUnits',
        'TableMaxWriteCapacityUnits',
    ):
        assert isinstance(limits1[key], int) and limits1[key] > 0, limits1
    assert limits1['TableMaxReadCapacityUnits'] <= limits1['AccountMaxReadCapacityUnits'], limits1
    assert limits1['TableMaxWriteCapacityUnits'] <= limits1['AccountMaxWriteCapacityUnits'], limits1

    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    limits2 = ddb.describe_limits()
    assert limits2['AccountMaxReadCapacityUnits'] == limits1['AccountMaxReadCapacityUnits'], (limits1, limits2)
    assert limits2['AccountMaxWriteCapacityUnits'] == limits1['AccountMaxWriteCapacityUnits'], (limits1, limits2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
