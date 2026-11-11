"""zero-at-exponent-boundary-rejected-one-step-past-range."""
from __future__ import annotations

from decimal import Decimal

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "zero-at-exponent-boundary-rejected-one-step-past-range"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

_OVERFLOW_MSG = (
    "1 validation error detected: Number overflow. Attempting to store a number with "
    "magnitude larger than supported range"
)
_UNDERFLOW_MSG = (
    "1 validation error detected: Number underflow. Attempting to store a number with "
    "magnitude smaller than supported range"
)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error']['Message']
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A zero's exponent is range-checked at the exact boundary: one exponent past the
    accepted ceiling or floor is rejected even though the value is still mathematically zero.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes.Number
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

    # --- positive control: zero at the accepted ceiling and floor is still accepted and
    # canonicalised to "0" ---
    for raw in ('0E125', '0E-130'):
        key = f'ok-{raw}'
        ddb.put_item(TableName=table, Item={'pk': {'S': key}, 'v': {'N': raw}})
        got = ddb.get_item(TableName=table, Key={'pk': {'S': key}}, ConsistentRead=True)['Item']
        assert got['v'] == {'N': '0'}, f'{raw!r} is mathematically zero and must canonicalise to "0", got {got["v"]}'
        assert Decimal(got['v']['N']) == 0, f'{raw!r} must round-trip as zero, got {got["v"]}'

    # --- one exponent past the ceiling is ValidationException: overflow, even though the
    # value is zero ---
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'over'}, 'v': {'N': '0E126'}}))
    assert code == ERR_VALIDATION, f'0E126 must be rejected with {ERR_VALIDATION}, got {code}'
    assert message == _OVERFLOW_MSG, f"expected AWS's exact overflow message, got {message!r}"
    leaked = ddb.get_item(TableName=table, Key={'pk': {'S': 'over'}}, ConsistentRead=True)
    assert 'Item' not in leaked, f'rejected write must not create the item, found {leaked.get("Item")}'

    # --- one exponent past the floor is ValidationException: underflow, even though the
    # value is zero ---
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'under'}, 'v': {'N': '0E-131'}}))
    assert code == ERR_VALIDATION, f'0E-131 must be rejected with {ERR_VALIDATION}, got {code}'
    assert message == _UNDERFLOW_MSG, f"expected AWS's exact underflow message, got {message!r}"
    leaked = ddb.get_item(TableName=table, Key={'pk': {'S': 'under'}}, ConsistentRead=True)
    assert 'Item' not in leaked, f'rejected write must not create the item, found {leaked.get("Item")}'

    # Control still works after every rejection.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ctrl'}, 'v': {'N': '42'}})
    ok = ddb.get_item(TableName=table, Key={'pk': {'S': 'ctrl'}}, ConsistentRead=True)['Item']
    assert ok['v'] == {'N': '42'}, f'control write must still succeed, got {ok!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
