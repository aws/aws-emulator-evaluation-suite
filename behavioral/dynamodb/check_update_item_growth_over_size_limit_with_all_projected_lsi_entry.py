"""update-item-growth-over-size-limit-with-all-projected-lsi-entry."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-growth-over-size-limit-with-all-projected-lsi-entry"
GROUP = 'limits'
SERVICES = ['dynamodb']
_OVER_LIMIT = ("ValidationException", "Item size to update has exceeded the maximum allowed size")
_GROWN_BYTES = 389800
_WAITER = {'Delay': 2, 'MaxAttempts': 90}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f'expected {code!r}, got {got_code!r} ({got_message!r})'
    assert got_message == message, f'unexpected message {got_message!r}'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem SET growth is sized against the item plus its ALL-projected local secondary
    index entry combined: growing to ~390 KB succeeds with no local secondary index but is
    refused ValidationException with one, leaving the pre-growth item unchanged."""
    ddb = ctx.client('dynamodb')
    plain_table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=plain_table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=plain_table))

    lsi_table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=lsi_table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
            {'AttributeName': 'li', 'AttributeType': 'S'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'li', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=lsi_table))

    ddb.get_waiter('table_exists').wait(TableName=plain_table, WaiterConfig=_WAITER)
    ddb.get_waiter('table_exists').wait(TableName=lsi_table, WaiterConfig=_WAITER)

    grown_value = 'y' * _GROWN_BYTES

    # Positive control: growing a small item to ~390 KB is under the ceiling on its own and is
    # accepted and reads back whole on a table with no local secondary index.
    ddb.put_item(TableName=plain_table, Item={'pk': {'S': 'upd-plain'}, 'sk': {'N': '1'}})
    ddb.update_item(
        TableName=plain_table, Key={'pk': {'S': 'upd-plain'}, 'sk': {'N': '1'}},
        UpdateExpression='SET #d = :v', ExpressionAttributeNames={'#d': 'data'},
        ExpressionAttributeValues={':v': {'S': grown_value}},
    )
    got = ddb.get_item(TableName=plain_table, Key={'pk': {'S': 'upd-plain'}, 'sk': {'N': '1'}},
                        ConsistentRead=True).get('Item', {})
    assert got.get('data', {}).get('S') == grown_value, (
        f'growing to {_GROWN_BYTES} bytes must round-trip whole through UpdateItem, '
        f'got {len(got.get("data", {}).get("S", ""))} bytes back'
    )

    # UpdateItem: the same small item, now on a table whose ALL-projected local secondary index
    # mirrors it, starts with an index entry already in place; growing it the same way is refused
    # because the combined (base item + index entry) size would exceed the 400 KB ceiling.
    ddb.put_item(TableName=lsi_table, Item={'pk': {'S': 'upd-lsi'}, 'sk': {'N': '1'}, 'li': {'S': 'idx'}})
    expect_error(
        lambda: ddb.update_item(
            TableName=lsi_table, Key={'pk': {'S': 'upd-lsi'}, 'sk': {'N': '1'}},
            UpdateExpression='SET #d = :v', ExpressionAttributeNames={'#d': 'data'},
            ExpressionAttributeValues={':v': {'S': grown_value}},
        ),
        *_OVER_LIMIT,
    )
    unchanged = ddb.get_item(TableName=lsi_table, Key={'pk': {'S': 'upd-lsi'}, 'sk': {'N': '1'}},
                              ConsistentRead=True).get('Item', {})
    assert 'data' not in unchanged, (
        f'the refused growth must leave the pre-growth item unchanged, got {sorted(unchanged)!r}'
    )
    assert unchanged.get('li', {}).get('S') == 'idx', (
        f'the pre-growth item must still be intact, got li={unchanged.get("li")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
