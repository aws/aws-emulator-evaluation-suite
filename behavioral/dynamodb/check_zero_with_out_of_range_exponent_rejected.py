"""zero-with-out-of-range-exponent-rejected."""
from __future__ import annotations

from decimal import Decimal

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "zero-with-out-of-range-exponent-rejected"
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

# Exponents on either side of Long.MAX_VALUE (9223372036854775807): one still parses as an
# integer and is then range-checked, the other overflows the parse itself.
_EXPONENT_AT_LONG_MAX = '9223372036854775807'
_EXPONENT_PAST_LONG_MAX = '9223372036854775808'


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error']['Message']
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A zero written with an out-of-range exponent is ValidationException even though its
    value is zero, while an in-range exponent is accepted and canonicalised to "0"; an
    unparseable exponent gets a different message than one that merely overflows.

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

    # --- positive control: zero with an IN-RANGE exponent is accepted and canonicalised ---
    for raw in ('0E125', '0E-130', '0E5'):
        key = f'ok-{raw}'
        ddb.put_item(TableName=table, Item={'pk': {'S': key}, 'v': {'N': raw}})
        got = ddb.get_item(TableName=table, Key={'pk': {'S': key}}, ConsistentRead=True)['Item']
        assert got['v'] == {'N': '0'}, f'{raw!r} is mathematically zero and must canonicalise to "0", got {got["v"]}'
        assert Decimal(got['v']['N']) == 0, f'{raw!r} must round-trip as zero, got {got["v"]}'

    # --- zero with an exponent past the documented ceiling is ValidationException: overflow ---
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'over'}, 'v': {'N': '0E+300'}}))
    assert code == ERR_VALIDATION, f'0E+300 must be rejected with {ERR_VALIDATION}, got {code}'
    assert message == _OVERFLOW_MSG, f"expected AWS's exact overflow message, got {message!r}"
    leaked = ddb.get_item(TableName=table, Key={'pk': {'S': 'over'}}, ConsistentRead=True)
    assert 'Item' not in leaked, f'rejected write must not create the item, found {leaked.get("Item")}'

    # --- zero with an exponent past the documented floor is ValidationException: underflow ---
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'under'}, 'v': {'N': '0E-300'}}))
    assert code == ERR_VALIDATION, f'0E-300 must be rejected with {ERR_VALIDATION}, got {code}'
    assert message == _UNDERFLOW_MSG, f"expected AWS's exact underflow message, got {message!r}"
    leaked = ddb.get_item(TableName=table, Key={'pk': {'S': 'under'}}, ConsistentRead=True)
    assert 'Item' not in leaked, f'rejected write must not create the item, found {leaked.get("Item")}'

    # --- an exponent that still parses as an integer (Long.MAX_VALUE) is range-checked and
    # overflows with the same message as any other out-of-range magnitude ---
    at_max_exp = f'1E{_EXPONENT_AT_LONG_MAX}'
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'exp-at-max'}, 'v': {'N': at_max_exp}}))
    assert code == ERR_VALIDATION, f'{at_max_exp!r} must be rejected with {ERR_VALIDATION}, got {code}'
    assert message == _OVERFLOW_MSG, f"expected AWS's exact overflow message, got {message!r}"

    # --- an exponent one past that integer's range cannot even be parsed, and gets the
    # "cannot be converted" message instead of the overflow message ---
    past_max_exp = f'1E{_EXPONENT_PAST_LONG_MAX}'
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'exp-past-max'}, 'v': {'N': past_max_exp}}))
    assert code == ERR_VALIDATION, f'{past_max_exp!r} must be rejected with {ERR_VALIDATION}, got {code}'
    assert message == f'1 validation error detected: The parameter cannot be converted to a numeric value: {past_max_exp}', (
        f"expected AWS's exact message, got {message!r}"
    )

    # Control still works after every rejection.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ctrl'}, 'v': {'N': '42'}})
    ok = ddb.get_item(TableName=table, Key={'pk': {'S': 'ctrl'}}, ConsistentRead=True)['Item']
    assert ok['v'] == {'N': '42'}, f'control write must still succeed, got {ok!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
