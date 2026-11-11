"""transact-write-items-put-and-update-accept-flat-409600-byte-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-put-and-update-accept-flat-409600-byte-item"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_TXN_CANCELLED = 'TransactionCanceledException'
LIMIT_BYTES = 409600


def _item_of_size(pk_value: str, filler_attr: str, total_bytes: int) -> dict:
    """A one-pk, one-filler-attribute item whose aggregate encoded size is exactly total_bytes."""
    overhead = len('pk'.encode()) + len(pk_value.encode()) + len(filler_attr.encode())
    filler_len = total_bytes - overhead
    assert filler_len > 0, f'{total_bytes} bytes is too small for this item shape'
    return {'pk': {'S': pk_value}, filler_attr: {'S': 'x' * filler_len}}


def _stored_item_size(item: dict) -> int:
    """The item's encoded size: every attribute name's bytes plus its string value's bytes."""
    total = 0
    for name, value in item.items():
        (type_code, raw), = value.items()
        assert type_code == 'S', f'attribute {name!r} is type {type_code!r}, expected S'
        total += len(name.encode()) + len(raw.encode())
    return total


def _error_code_and_message(fn) -> tuple[str, str]:
    """The Error Code and Message ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems Put and Update accept an item whose flat encoded size, key included, is
    exactly 409600 bytes; an Update growing an item one byte past it cancels with a ValidationError
    reason and leaves the item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    # TransactWriteItems Put of an item at exactly the flat 409600-byte limit is accepted
    # and reads back whole, so the key's own bytes are not excluded from the count.
    put_pk = ctx.unique_name('sim2real-behav-put-')
    put_item = _item_of_size(put_pk, 'data', LIMIT_BYTES)
    ddb.transact_write_items(TransactItems=[{'Put': {'TableName': table, 'Item': put_item}}])
    put_got = ddb.get_item(TableName=table, Key={'pk': {'S': put_pk}}, ConsistentRead=True)
    assert 'Item' in put_got, f'a {LIMIT_BYTES}-byte TransactWriteItems Put must persist, got none'
    assert put_got['Item']['data']['S'] == put_item['data']['S'], (
        f'a {LIMIT_BYTES}-byte item must round-trip whole through TransactWriteItems Put, '
        f'got {len(put_got["Item"]["data"]["S"])} bytes back'
    )
    assert _stored_item_size(put_got['Item']) == LIMIT_BYTES, (
        f'stored item size is {_stored_item_size(put_got["Item"])}, expected {LIMIT_BYTES}'
    )

    # TransactWriteItems Update that grows a stored item to exactly the same flat
    # 409600-byte limit is accepted too.
    update_pk = ctx.unique_name('sim2real-behav-upd-')
    ddb.put_item(TableName=table, Item={'pk': {'S': update_pk}, 'data': {'S': 'start'}})
    overhead = len('pk'.encode()) + len(update_pk.encode()) + len('data'.encode())
    grown_value = 'g' * (LIMIT_BYTES - overhead)
    ddb.transact_write_items(TransactItems=[{'Update': {
        'TableName': table,
        'Key': {'pk': {'S': update_pk}},
        'UpdateExpression': 'SET #d = :v',
        'ExpressionAttributeNames': {'#d': 'data'},
        'ExpressionAttributeValues': {':v': {'S': grown_value}},
    }}])
    update_got = ddb.get_item(TableName=table, Key={'pk': {'S': update_pk}}, ConsistentRead=True)
    assert update_got['Item']['data']['S'] == grown_value, (
        f'the grown value must round-trip whole through TransactWriteItems Update, '
        f'got {len(update_got["Item"]["data"]["S"])} bytes back'
    )
    assert _stored_item_size(update_got['Item']) == LIMIT_BYTES, (
        f'stored item size is {_stored_item_size(update_got["Item"])}, expected {LIMIT_BYTES}'
    )

    # The focus: a TransactWriteItems Update that would grow a stored item one byte past
    # the same flat limit is refused, and the stored item is left unchanged.
    over_pk = ctx.unique_name('sim2real-behav-over-')
    ddb.put_item(TableName=table, Item={'pk': {'S': over_pk}, 'data': {'S': 'start'}})
    overhead_over = len('pk'.encode()) + len(over_pk.encode()) + len('data'.encode())
    over_value = 'g' * (LIMIT_BYTES + 1 - overhead_over)
    code, message = _error_code_and_message(lambda: ddb.transact_write_items(TransactItems=[{'Update': {
        'TableName': table,
        'Key': {'pk': {'S': over_pk}},
        'UpdateExpression': 'SET #d = :v',
        'ExpressionAttributeNames': {'#d': 'data'},
        'ExpressionAttributeValues': {':v': {'S': over_value}},
    }}]))
    assert code == ERR_TXN_CANCELLED, (
        f'a TransactWriteItems Update growing an item one byte past {LIMIT_BYTES} bytes '
        f'must be {ERR_TXN_CANCELLED}, got {code!r}: {message!r}'
    )
    assert message == (
        'Transaction cancelled, please refer cancellation reasons for specific reasons [ValidationError]'
    ), f"expected AWS's exact TransactionCanceledException message, got {message!r}"

    unchanged = ddb.get_item(TableName=table, Key={'pk': {'S': over_pk}}, ConsistentRead=True)
    assert unchanged['Item']['data']['S'] == 'start', (
        f'a TransactWriteItems Update rejected for size must leave the item unchanged, '
        f'got {unchanged.get("Item")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
