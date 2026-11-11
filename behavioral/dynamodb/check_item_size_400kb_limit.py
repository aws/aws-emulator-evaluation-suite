"""item-size-400kb-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "item-size-400kb-limit"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem of a 400 KB attribute raises ValidationException with the exact message and stores nothing, while a
    small item and a 399 KB item on the same table read back whole.
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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: a small item on the same wiring must succeed, so a target that
    # rejects every PutItem (not just oversized ones) cannot pass this check.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'small'}, 'data': {'S': 'ok'}})
    control = ddb.get_item(TableName=table, Key={'pk': {'S': 'small'}}, ConsistentRead=True)
    assert control.get('Item', {}).get('data', {}).get('S') == 'ok', (
        f'positive control PutItem/GetItem round-trip failed, got {control.get("Item")}'
    )

    # The boundary itself: an item just under 400 KB (attribute names + values) is accepted and
    # reads back whole, so a target with any lower size cap fails here.
    near_value = 'n' * (399 * 1024)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'near'}, 'data': {'S': near_value}})
    near = ddb.get_item(TableName=table, Key={'pk': {'S': 'near'}}, ConsistentRead=True)
    near_len = len(near.get('Item', {}).get('data', {}).get('S', ''))
    assert near_len == len(near_value), (
        f'expected the {len(near_value)}-byte near-limit attribute to read back whole, got {near_len} bytes'
    )

    big_value = 'x' * (400 * 1024)
    exc = _expect_error(lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'big'}, 'data': {'S': big_value}}),
                        (ERR_VALIDATION,))
    message = exc.response['Error'].get('Message')
    assert message == 'Item size has exceeded the maximum allowed size', (
        f'an over-400 KB PutItem: got the message {message!r}'
    )

    # Independent read at the destination: the rejected write must not have persisted.
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'big'}}, ConsistentRead=True)
    assert 'Item' not in got, f'oversized item must not persist after rejection, got {got.get("Item")}'


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, a non-empty message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected a non-empty message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
