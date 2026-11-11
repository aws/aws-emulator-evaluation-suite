"""item-size-boundary-across-multiple-long-attribute-names."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "item-size-boundary-across-multiple-long-attribute-names"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_MESSAGE = 'Item size has exceeded the maximum allowed size'
LIMIT_BYTES = 409600


def _attr_name(i: int) -> str:
    """A unique, exactly-27-character attribute name."""
    prefix = f'payload-attr-{i:02d}-'
    name = prefix + 'n' * (27 - len(prefix))
    assert len(name) == 27, f'helper built a {len(name)}-char name, expected 27: {name!r}'
    return name


def _item_of_size(pk_value: str, names: list, total_bytes: int) -> dict:
    """An item whose ``pk`` plus every attribute in ``names`` sums to exactly total_bytes,
    counting each attribute's name and value length."""
    fixed = len('pk'.encode()) + len(pk_value.encode()) + sum(len(n.encode()) for n in names)
    payload_bytes = total_bytes - fixed
    n = len(names)
    assert payload_bytes >= n, f'{total_bytes} bytes is too small for {n} named attributes'
    base, extra = divmod(payload_bytes, n)
    item = {'pk': {'S': pk_value}}
    for idx, name in enumerate(names):
        length = base + (extra if idx == 0 else 0)
        item[name] = {'S': 'x' * length}
    return item


def _error_code_and_message(fn) -> tuple:
    """The Error Code and Message ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each attribute name's byte length is summed into the item size alongside its value:
    the 409600/409601 boundary holds byte-exact with 2 and 10 payload attributes named 27
    characters each, for both PutItem and BatchWriteItem PutRequest.
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

    names_2 = [_attr_name(i) for i in range(2)]
    names_10 = [_attr_name(i) for i in range(10)]

    # PutItem, 2 payload attributes: exactly at the limit is accepted and reads back whole,
    # byte-exact in every attribute including its 27-character name.
    at_item = _item_of_size('put-2attr-at-limit', names_2, LIMIT_BYTES)
    ddb.put_item(TableName=table, Item=at_item)
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'put-2attr-at-limit'}}, ConsistentRead=True).get('Item', {})
    assert sorted(got) == sorted(['pk'] + names_2), (
        f'a {LIMIT_BYTES}-byte item across 2 named attributes must read back all of them, got {sorted(got)!r}'
    )
    assert all(got[n] == at_item[n] for n in names_2), (
        f'every 27-char-named attribute must read back byte-identical, got {got!r}'
    )

    # PutItem, 2 payload attributes: one byte over is rejected and nothing is stored.
    over_item = _item_of_size('put-2attr-over-limit', names_2, LIMIT_BYTES + 1)
    code, message = _error_code_and_message(lambda: ddb.put_item(TableName=table, Item=over_item))
    assert code == ERR_VALIDATION, (
        f'a {LIMIT_BYTES + 1}-byte PutItem across 2 named attributes must be {ERR_VALIDATION}, got {code!r}'
    )
    assert message == ERR_MESSAGE, f"expected AWS's exact ValidationException message, got {message!r}"
    rejected = ddb.get_item(TableName=table, Key={'pk': {'S': 'put-2attr-over-limit'}}, ConsistentRead=True)
    assert 'Item' not in rejected, f'a PutItem rejected for size must not persist, got {rejected.get("Item")}'

    # BatchWriteItem PutRequest, 10 payload attributes: exactly at the limit is accepted and
    # reads back whole.
    at_item10 = _item_of_size('batch-10attr-at-limit', names_10, LIMIT_BYTES)
    bw_resp = ddb.batch_write_item(RequestItems={table: [{'PutRequest': {'Item': at_item10}}]})
    assert bw_resp.get('UnprocessedItems', {}) == {}, (
        f'a {LIMIT_BYTES}-byte BatchWriteItem PutRequest across 10 named attributes must fully '
        f'process, got UnprocessedItems={bw_resp.get("UnprocessedItems")!r}'
    )
    got10 = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'batch-10attr-at-limit'}}, ConsistentRead=True
    ).get('Item', {})
    assert sorted(got10) == sorted(['pk'] + names_10), (
        f'a {LIMIT_BYTES}-byte item across 10 named attributes must read back all of them, got {sorted(got10)!r}'
    )
    assert all(got10[n] == at_item10[n] for n in names_10), (
        f'every 27-char-named attribute must read back byte-identical, got {got10!r}'
    )

    # BatchWriteItem PutRequest, 10 payload attributes: one byte over is rejected and nothing
    # is stored.
    over_item10 = _item_of_size('batch-10attr-over-limit', names_10, LIMIT_BYTES + 1)
    bw_code, bw_message = _error_code_and_message(
        lambda: ddb.batch_write_item(RequestItems={table: [{'PutRequest': {'Item': over_item10}}]})
    )
    assert bw_code == ERR_VALIDATION, (
        f'a {LIMIT_BYTES + 1}-byte BatchWriteItem PutRequest across 10 named attributes must be '
        f'{ERR_VALIDATION}, got {bw_code!r}'
    )
    assert bw_message == ERR_MESSAGE, f"expected AWS's exact ValidationException message, got {bw_message!r}"
    bw_rejected = ddb.get_item(TableName=table, Key={'pk': {'S': 'batch-10attr-over-limit'}}, ConsistentRead=True)
    assert 'Item' not in bw_rejected, (
        f'a BatchWriteItem PutRequest rejected for size must not persist, got {bw_rejected.get("Item")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
