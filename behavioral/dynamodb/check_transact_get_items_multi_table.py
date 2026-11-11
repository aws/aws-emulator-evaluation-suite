"""transact-get-items-multi-table."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-get-items-multi-table"
GROUP = 'transactions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactGetItems returns a single atomic-snapshot response spanning MULTIPLE distinct
    tables, each Get slot resolved against the correct table and in request order (a missing key
    resolves to an empty slot, not an error).
    """
    ddb = ctx.client('dynamodb')
    table_a = _simple_table(ctx, ddb, 'sim2real-behav-tgi-a-')
    table_b = _simple_table(ctx, ddb, 'sim2real-behav-tgi-b-')
    ddb.put_item(TableName=table_a, Item={'pk': {'S': 'x'}, 'src': {'S': 'a'}})
    ddb.put_item(TableName=table_b, Item={'pk': {'S': 'x'}, 'src': {'S': 'b'}})

    resp = ddb.transact_get_items(
        TransactItems=[
            {'Get': {'TableName': table_a, 'Key': {'pk': {'S': 'x'}}}},
            {'Get': {'TableName': table_b, 'Key': {'pk': {'S': 'x'}}}},
            {'Get': {'TableName': table_a, 'Key': {'pk': {'S': 'does-not-exist'}}}},
        ]
    )
    responses = resp['Responses']
    assert len(responses) == 3, f'expected 3 response slots, got {len(responses)}: {responses!r}'
    assert responses[0]['Item']['src'] == {'S': 'a'}, (
        f'slot 0 must resolve against table_a, got {responses[0]!r}'
    )
    assert responses[1]['Item']['src'] == {'S': 'b'}, (
        f'slot 1 must resolve against table_b, got {responses[1]!r}'
    )
    assert responses[2] == {}, (
        f'missing key on table_a must resolve to an empty slot, not an error, got {responses[2]!r}'
    )


def _simple_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda n=name: ddb.delete_table(TableName=n))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
