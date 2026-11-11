"""put-item-and-batch-write-item-binary-item-size-boundary-raw-bytes."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-and-batch-write-item-binary-item-size-boundary-raw-bytes"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
LIMIT_BYTES = 409600


def _item_of_size(pk_value: str, filler_attr: str, total_bytes: int) -> dict:
    """A one-pk, one-filler-attribute item whose aggregate size (name plus raw Binary bytes,
    never base64 text) is total_bytes."""
    overhead = len('pk'.encode()) + len(pk_value.encode()) + len(filler_attr.encode())
    filler_len = total_bytes - overhead
    assert filler_len > 0, f'{total_bytes} bytes is too small for this item shape'
    return {'pk': {'S': pk_value}, filler_attr: {'B': b'x' * filler_len}}


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
    """The 400 KB item-size gate sizes a Binary attribute by its decoded raw byte length, not
    its base64 text length: accepted at exactly 409600 raw bytes, refused one raw byte over,
    for both PutItem and BatchWriteItem.

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

    # PutItem: a Binary attribute at exactly 409600 raw bytes is accepted and round-trips,
    # even though its base64 text is already longer than 409600 characters.
    at_limit = _item_of_size('put-at-limit', 'data', LIMIT_BYTES)
    base64_len_at_limit = len(base64.b64encode(at_limit['data']['B']))
    assert base64_len_at_limit > LIMIT_BYTES, (
        f'the fixture must exercise raw-vs-base64 divergence; base64 text was only '
        f'{base64_len_at_limit} chars for a {LIMIT_BYTES}-raw-byte attribute'
    )
    ddb.put_item(TableName=table, Item=at_limit)
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'put-at-limit'}}, ConsistentRead=True)
    stored = got.get('Item', {}).get('data', {}).get('B', b'')
    assert stored == at_limit['data']['B'], (
        f'a 409600-raw-byte Binary item must round-trip whole through PutItem, '
        f'got {len(stored)} raw bytes back'
    )

    # PutItem: one raw byte over is rejected and nothing is stored.
    over = _item_of_size('put-over-limit', 'data', LIMIT_BYTES + 1)
    code, message = _error_code_and_message(lambda: ddb.put_item(TableName=table, Item=over))
    assert code == ERR_VALIDATION, (
        f'a {LIMIT_BYTES + 1}-raw-byte Binary PutItem must be {ERR_VALIDATION}, got {code!r}: {message!r}'
    )
    assert message == 'Item size has exceeded the maximum allowed size', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    rejected = ddb.get_item(TableName=table, Key={'pk': {'S': 'put-over-limit'}}, ConsistentRead=True)
    assert 'Item' not in rejected, (
        f'a PutItem rejected for size must not persist, got {rejected.get("Item")}'
    )

    # BatchWriteItem PutRequest: exactly at the raw-byte limit is accepted and round-trips.
    bw_at_limit = _item_of_size('batch-at-limit', 'data', LIMIT_BYTES)
    bw_resp = ddb.batch_write_item(RequestItems={table: [{'PutRequest': {'Item': bw_at_limit}}]})
    assert bw_resp.get('UnprocessedItems', {}) == {}, (
        f'a 409600-raw-byte Binary BatchWriteItem PutRequest must fully process, '
        f'got UnprocessedItems={bw_resp.get("UnprocessedItems")!r}'
    )
    bw_got = ddb.get_item(TableName=table, Key={'pk': {'S': 'batch-at-limit'}}, ConsistentRead=True)
    bw_stored = bw_got.get('Item', {}).get('data', {}).get('B', b'')
    assert bw_stored == bw_at_limit['data']['B'], (
        f'a 409600-raw-byte Binary item must round-trip whole through BatchWriteItem, '
        f'got {len(bw_stored)} raw bytes back'
    )

    # BatchWriteItem PutRequest: one raw byte over is rejected and nothing is stored.
    bw_over = _item_of_size('batch-over-limit', 'data', LIMIT_BYTES + 1)
    bw_code, bw_message = _error_code_and_message(
        lambda: ddb.batch_write_item(RequestItems={table: [{'PutRequest': {'Item': bw_over}}]})
    )
    assert bw_code == ERR_VALIDATION, (
        f'a {LIMIT_BYTES + 1}-raw-byte Binary BatchWriteItem PutRequest must be '
        f'{ERR_VALIDATION}, got {bw_code!r}: {bw_message!r}'
    )
    assert bw_message == 'Item size has exceeded the maximum allowed size', (
        f"expected AWS's exact ValidationException message, got {bw_message!r}"
    )
    bw_rejected = ddb.get_item(TableName=table, Key={'pk': {'S': 'batch-over-limit'}}, ConsistentRead=True)
    assert 'Item' not in bw_rejected, (
        f'a BatchWriteItem PutRequest rejected for size must not persist, got {bw_rejected.get("Item")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
