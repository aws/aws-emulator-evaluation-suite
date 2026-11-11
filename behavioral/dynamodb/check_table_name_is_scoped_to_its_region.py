"""table-name-is-scoped-to-its-region."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-name-is-scoped-to-its-region"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']

ERR_NOT_FOUND = 'ResourceNotFoundException'


def _second_region(primary):
    """A region distinct from the primary. Which one does not matter -- only that it differs, so the
    check cannot pass on an implementation that ignores the region entirely."""
    return 'us-west-2' if primary != 'us-west-2' else 'us-east-1'


def _code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _drop(client, table):
    """Cleanup that tolerates the table already being gone -- this check deletes one of the two
    tables as part of its assertions, so its cleanup must be idempotent."""
    try:
        client.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != ERR_NOT_FOUND:
            raise


def _all_table_names(client):
    """ListTables pages at 100 names, and a shared account can hold more than that."""
    names = []
    kwargs = {}
    while True:
        page = client.list_tables(**kwargs)
        names.extend(page['TableNames'])
        last = page.get('LastEvaluatedTableName')
        if not last:
            return names
        kwargs = {'ExclusiveStartTableName': last}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A table name is scoped to its region: before it exists in the second region DescribeTable there raises
    ResourceNotFoundException with the exact message, the two same-named tables keep separate items and listings,
    and deleting one leaves the other and its item intact.
    """
    primary = ctx.region
    secondary = _second_region(primary)
    ddb_a = ctx.client('dynamodb')
    ddb_b = ctx.client('dynamodb', region=secondary)
    table = ctx.unique_name('sim2real-behav-region-')

    def _create(client):
        client.create_table(
            TableName=table,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
            Tags=[{'Key': 'sim2real', 'Value': CHECK}],
        )
        client.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- before the second region has the name, it does not resolve there ---
    _create(ddb_a)
    ctx.on_cleanup(lambda: _drop(ddb_a, table))
    code, message = _code(lambda: ddb_b.describe_table(TableName=table))
    assert code == ERR_NOT_FOUND, (
        f'a table created in {primary!r} must not resolve in {secondary!r}: DescribeTable there '
        f'must fail with {ERR_NOT_FOUND}, got {code}'
    )
    assert message == f"Requested resource not found: Table: {table} not found", (
        f"expected AWS's exact ResourceNotFoundException message, got {message!r}"
    )

    _create(ddb_b)
    ctx.on_cleanup(lambda: _drop(ddb_b, table))

    # --- each region lists only its own table, and both are ACTIVE independently ---
    for client, region in ((ddb_a, primary), (ddb_b, secondary)):
        described = client.describe_table(TableName=table)['Table']
        assert described['TableStatus'] == 'ACTIVE', (
            f'the table in {region!r} must be ACTIVE in its own right, got '
            f'{described["TableStatus"]!r}'
        )
        assert region in described['TableArn'], (
            f'the ARN of the table in {region!r} must name that region, got '
            f'{described["TableArn"]!r}'
        )

    # --- items written in one region are invisible in the other ---
    ddb_a.put_item(TableName=table, Item={'pk': {'S': 'shared-key'}, 'home': {'S': primary}})
    ddb_b.put_item(TableName=table, Item={'pk': {'S': 'shared-key'}, 'home': {'S': secondary}})
    for client, region in ((ddb_a, primary), (ddb_b, secondary)):
        got = client.get_item(
            TableName=table, Key={'pk': {'S': 'shared-key'}}, ConsistentRead=True,
        ).get('Item')
        assert got == {'pk': {'S': 'shared-key'}, 'home': {'S': region}}, (
            f'the same key in {region!r} must hold that region\'s own item, not the other '
            f'region\'s: got {got!r}'
        )

    # --- an item written in only one region does not appear in the other ---
    ddb_a.put_item(TableName=table, Item={'pk': {'S': 'primary-only'}})
    absent = ddb_b.get_item(
        TableName=table, Key={'pk': {'S': 'primary-only'}}, ConsistentRead=True,
    )
    assert 'Item' not in absent, (
        f'an item written only in {primary!r} must be absent in {secondary!r}, found '
        f'{absent.get("Item")!r}'
    )

    # --- deleting one region's table leaves the other's table and data intact ---
    ddb_b.delete_table(TableName=table)
    ddb_b.get_waiter('table_not_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    survivor = ddb_a.get_item(
        TableName=table, Key={'pk': {'S': 'shared-key'}}, ConsistentRead=True,
    ).get('Item')
    assert survivor == {'pk': {'S': 'shared-key'}, 'home': {'S': primary}}, (
        f'deleting the table in {secondary!r} must not touch the table in {primary!r} or its '
        f'items, got {survivor!r}'
    )
    assert table in _all_table_names(ddb_a), (
        f'the table in {primary!r} must still be listed after the {secondary!r} table was deleted'
    )
    assert table not in _all_table_names(ddb_b), (
        f'the deleted table must no longer be listed in {secondary!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
