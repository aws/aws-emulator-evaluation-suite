"""transact-update-condition-needs-item-cancels-the-passing-sibling."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-update-condition-needs-item-cancels-the-passing-sibling"
GROUP = 'conditions'
SERVICES = ['dynamodb']

_CCF = ('ConditionalCheckFailedException', 'The conditional request failed')
_CANCELED_FIRST_FAILS = (
    'TransactionCanceledException',
    'Transaction cancelled, please refer cancellation reasons for specific reasons '
    '[ConditionalCheckFailed, None]',
)


def _expect_error(fn, code, message):
    """Call fn() and grade the exact (code, message) it raises; a success is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response['Error'].get('Code')
        got_message = exc.response['Error'].get('Message')
        assert got_code == code, f"expected {code!r}, got {got_code!r}: {got_message!r}"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return exc
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise
    return run_undo


_WAIT_S = 60.0


def _wait_table_active(ddb, table, timeout_s=_WAIT_S) -> None:
    """Poll DescribeTable until the table is ACTIVE; on expiry fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)['Table']['TableStatus']
        if status == 'ACTIVE':
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last status {status!r}")
        time.sleep(1.0)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Update whose own condition needs an absent item cancels the whole
    transaction, rolling back a sibling Update whose own condition already held. The same rule
    rejects a standalone UpdateItem with a plain comparison condition and creates nothing."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), 'ResourceNotFoundException'))
    _wait_table_active(ddb, table)

    ghost_key = {'id': {'S': 'ghost-order'}}
    sibling_key = {'id': {'S': 'sibling-counter'}}
    sibling_seed = {**sibling_key, 'count': {'N': '10'}}
    ddb.put_item(TableName=table, Item=sibling_seed)

    def transfer():
        return ddb.transact_write_items(TransactItems=[
            {'Update': {
                'TableName': table, 'Key': ghost_key,
                'UpdateExpression': 'SET #st = :s',
                'ConditionExpression': 'attribute_exists(id) AND version = :v',
                'ExpressionAttributeNames': {'#st': 'status'},
                'ExpressionAttributeValues': {':s': {'S': 'filled'}, ':v': {'N': '1'}},
            }},
            {'Update': {
                'TableName': table, 'Key': sibling_key,
                'UpdateExpression': 'SET #c = #c + :inc',
                'ConditionExpression': '#c = :expected',
                'ExpressionAttributeNames': {'#c': 'count'},
                'ExpressionAttributeValues': {':inc': {'N': '1'}, ':expected': {'N': '10'}},
            }},
        ])

    exc = _expect_error(transfer, *_CANCELED_FIRST_FAILS)
    reasons = [(r.get('Code'), r.get('Message')) for r in exc.response.get('CancellationReasons', [])]
    assert reasons == [('ConditionalCheckFailed', 'The conditional request failed'), ('None', None)], (
        f"expected [ConditionalCheckFailed, None] cancellation reasons, got {reasons!r}"
    )

    ghost_got = ddb.get_item(TableName=table, Key=ghost_key, ConsistentRead=True).get('Item')
    assert ghost_got is None, f"the cancelled transaction's own ghost key must stay absent, got {ghost_got!r}"
    sibling_got = ddb.get_item(TableName=table, Key=sibling_key, ConsistentRead=True).get('Item')
    assert sibling_got == sibling_seed, (
        f"the sibling Update's own condition held, but it must still be rolled back: got {sibling_got!r}"
    )

    # Positive control: create the ghost item for real, then the identical transaction commits both.
    ghost_seed = {**ghost_key, 'version': {'N': '1'}, 'status': {'S': 'new'}}
    ddb.put_item(TableName=table, Item=ghost_seed)
    transfer()
    ghost_after = ddb.get_item(TableName=table, Key=ghost_key, ConsistentRead=True).get('Item')
    assert ghost_after == {**ghost_key, 'version': {'N': '1'}, 'status': {'S': 'filled'}}, (
        f"expected the committed transaction to flip status to filled, got {ghost_after!r}"
    )
    sibling_after = ddb.get_item(TableName=table, Key=sibling_key, ConsistentRead=True).get('Item')
    assert sibling_after == {**sibling_key, 'count': {'N': '11'}}, (
        f"expected the committed transaction to bump the sibling's count to 11, got {sibling_after!r}"
    )

    # Standalone UpdateItem, a pure comparison condition (no attribute_exists), on an absent key.
    lonely_key = {'id': {'S': 'lonely-widget'}}

    def restock():
        return ddb.update_item(
            TableName=table, Key=lonely_key,
            UpdateExpression='SET stock = :s',
            ConditionExpression='stock > :zero',
            ExpressionAttributeValues={':s': {'N': '5'}, ':zero': {'N': '0'}},
        )

    _expect_error(restock, *_CCF)
    lonely_got = ddb.get_item(TableName=table, Key=lonely_key, ConsistentRead=True).get('Item')
    assert lonely_got is None, f"the rejected standalone update must create nothing, got {lonely_got!r}"

    # Positive control: once the item exists with a satisfying value, the identical call commits.
    ddb.put_item(TableName=table, Item={**lonely_key, 'stock': {'N': '3'}})
    restock()
    lonely_after = ddb.get_item(TableName=table, Key=lonely_key, ConsistentRead=True).get('Item')
    assert lonely_after == {**lonely_key, 'stock': {'N': '5'}}, (
        f"expected the restored conditional update to land, got {lonely_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
