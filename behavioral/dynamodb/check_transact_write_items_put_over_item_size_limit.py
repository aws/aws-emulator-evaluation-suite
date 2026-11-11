"""transact-write-items-put-over-item-size-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-put-over-item-size-limit"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
LIMIT_BYTES = 409600


def _item_of_size(pk_value: str, filler_attr: str, total_bytes: int) -> dict:
    """A one-pk, one-filler-attribute item whose aggregate encoded size is exactly total_bytes."""
    overhead = len('pk'.encode()) + len(pk_value.encode()) + len(filler_attr.encode())
    filler_len = total_bytes - overhead
    assert filler_len > 0, f'{total_bytes} bytes is too small for this item shape'
    return {'pk': {'S': pk_value}, filler_attr: {'S': 'x' * filler_len}}


def _error_code_and_message(fn) -> tuple[str, str]:
    """The Error Code and Message ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Put of an item one byte over the size limit is refused as a
    top-level ValidationException, never a TransactionCanceledException, and writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
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

    # Positive control: TransactWriteItems Put of a normal item succeeds and reads back,
    # so a target that rejects every transaction (not just oversized ones) fails here.
    control_item = {'pk': {'S': 'control'}, 'data': {'S': 'ok'}}
    ddb.transact_write_items(TransactItems=[{'Put': {'TableName': table, 'Item': control_item}}])
    control_got = ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}}, ConsistentRead=True)
    assert control_got.get('Item', {}).get('data', {}).get('S') == 'ok', (
        f'positive control TransactWriteItems Put/GetItem round-trip failed, got {control_got.get("Item")}'
    )

    # The focus: an item one byte over the limit, put through TransactWriteItems.
    over_item = _item_of_size('over-limit', 'data', LIMIT_BYTES + 1)
    code, message = _error_code_and_message(lambda: ddb.transact_write_items(
        TransactItems=[{'Put': {'TableName': table, 'Item': over_item}}]
    ))
    assert code == ERR_VALIDATION, (
        f'a {LIMIT_BYTES + 1}-byte TransactWriteItems Put must be {ERR_VALIDATION}, '
        f'not TransactionCanceledException, got {code!r}: {message!r}'
    )
    assert message == 'Item size has exceeded the maximum allowed size', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    rejected = ddb.get_item(TableName=table, Key={'pk': {'S': 'over-limit'}}, ConsistentRead=True)
    assert 'Item' not in rejected, (
        f'a TransactWriteItems Put rejected for size must not persist, got {rejected.get("Item")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
