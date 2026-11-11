"""put-item-and-batch-write-item-size-limit-includes-all-projected-lsi-entry."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-and-batch-write-item-size-limit-includes-all-projected-lsi-entry"
GROUP = 'limits'
SERVICES = ['dynamodb']
_OVER_LIMIT = ("ValidationException", "Item size has exceeded the maximum allowed size")
_ITEM_BYTES = 390000
_WAITER = {'Delay': 2, 'MaxAttempts': 90}


def _item_of_size(pk_value: str, total_bytes: int) -> dict:
    """A pk/sk/li-keyed item whose aggregate encoded size is exactly ``total_bytes``."""
    overhead = (
        len(b'pk') + len(pk_value.encode())
        + len(b'sk') + len(b'1')
        + len(b'li') + len(b'idx')
        + len(b'data')
    )
    filler_len = total_bytes - overhead
    assert filler_len > 0, f'{total_bytes} bytes is too small for this item shape'
    return {
        'pk': {'S': pk_value},
        'sk': {'N': '1'},
        'li': {'S': 'idx'},
        'data': {'S': 'x' * filler_len},
    }


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
    """PutItem and BatchWriteItem PutRequest size a write against the item plus its ALL-projected
    local secondary index entry combined: a ~390 KB item is accepted with no local secondary
    index but refused ValidationException with one, storing nothing either way."""
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

    # Positive control: the same ~390 KB item is under the 400 KB ceiling on its own and is
    # accepted and reads back whole on a table with no local secondary index.
    plain_item = _item_of_size('put-plain', _ITEM_BYTES)
    ddb.put_item(TableName=plain_table, Item=plain_item)
    got = ddb.get_item(TableName=plain_table, Key={'pk': {'S': 'put-plain'}, 'sk': {'N': '1'}},
                        ConsistentRead=True).get('Item', {})
    assert got.get('data', {}).get('S') == plain_item['data']['S'], (
        f'a {_ITEM_BYTES}-byte item must round-trip whole through PutItem, got {len(got.get("data", {}).get("S", ""))} bytes back'
    )

    # PutItem: the same-sized item, now with an ALL-projected local secondary index mirroring it,
    # is refused — the combined (base item + index entry) size exceeds the 400 KB ceiling.
    put_item = _item_of_size('put-lsi', _ITEM_BYTES)
    expect_error(lambda: ddb.put_item(TableName=lsi_table, Item=put_item), *_OVER_LIMIT)
    rejected = ddb.get_item(TableName=lsi_table, Key={'pk': {'S': 'put-lsi'}, 'sk': {'N': '1'}},
                             ConsistentRead=True)
    assert 'Item' not in rejected, f'a PutItem rejected for size must not persist, got {rejected.get("Item")}'

    # BatchWriteItem PutRequest: the same combined-size rule applies.
    batch_item = _item_of_size('batch-lsi', _ITEM_BYTES)
    expect_error(
        lambda: ddb.batch_write_item(RequestItems={lsi_table: [{'PutRequest': {'Item': batch_item}}]}),
        *_OVER_LIMIT,
    )
    batch_rejected = ddb.get_item(TableName=lsi_table, Key={'pk': {'S': 'batch-lsi'}, 'sk': {'N': '1'}},
                                   ConsistentRead=True)
    assert 'Item' not in batch_rejected, (
        f'a BatchWriteItem PutRequest rejected for size must not persist, got {batch_rejected.get("Item")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
