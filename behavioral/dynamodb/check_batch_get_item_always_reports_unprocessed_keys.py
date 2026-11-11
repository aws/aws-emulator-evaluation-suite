"""batch-get-item-always-reports-unprocessed-keys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-item-always-reports-unprocessed-keys"
GROUP = 'batch'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """BatchGetItem always carries UnprocessedKeys, shaped like RequestItems so a caller can feed it
    straight back. Asserted by actually re-passing it, not by inspecting the type."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}})
    res = ddb.batch_get_item(RequestItems={table: {'Keys': [{'pk': {'S': 'a'}}]}})
    assert 'UnprocessedKeys' in res, (
        f"UnprocessedKeys must be present even when nothing was left over, got {sorted(res)}"
    )
    assert res['UnprocessedKeys'] == {}, (
        f"nothing was unprocessed, so the map must be empty rather than absent, got {res['UnprocessedKeys']}"
    )
    assert len(res['Responses'][table]) == 1, f"expected the one item back, got {res['Responses']}"
    # The contract is that the value is directly re-passable as RequestItems. Feeding the empty map
    # back must be accepted -- a target that returns a differently shaped placeholder fails here.
    again = ddb.batch_get_item(RequestItems={table: {'Keys': [{'pk': {'S': 'a'}}]},
                                             **res['UnprocessedKeys']})
    assert len(again['Responses'][table]) == 1, 're-passing UnprocessedKeys must be accepted'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
