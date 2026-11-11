"""number-precision-overflow-in-exponent-form-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "number-precision-overflow-in-exponent-form-rejected"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

# Both mantissas sit near the top of the magnitude range (exponent E124, one step below the
# documented ceiling's E125); only their significant-digit count differs.
_OK_MANTISSA = '9.' + '9' * 37       # 38 significant digits: at the documented precision limit
_OVER_MANTISSA = '9.' + '9' * 38     # 39 significant digits: one past the limit
_OK_INPUT = _OK_MANTISSA + 'E124'
_OVER_INPUT = _OVER_MANTISSA + 'E124'
_EXPECTED_OK = '9' * 38 + '0' * (125 - 38)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number written in exponent form is checked for 38-significant-digit precision after
    the exponent is folded: 39 significant digits is rejected even though the magnitude is
    well inside the documented range, and 38 at the same magnitude is accepted and stored.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- positive control: 38 significant digits in exponent form is accepted and expands ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'ok'}, 'v': {'N': _OK_INPUT}})
    ok_item = ddb.get_item(TableName=t, Key={'pk': {'S': 'ok'}}, ConsistentRead=True)['Item']
    assert ok_item['v'] == {'N': _EXPECTED_OK}, (
        f'{_OK_INPUT!r} (38 significant digits) must be accepted and stored as the expanded '
        f'plain-decimal string {_EXPECTED_OK!r}, got {ok_item["v"]}'
    )

    # --- 39 significant digits in exponent form is rejected with the 38-digit precision message ---
    code, message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'over'}, 'v': {'N': _OVER_INPUT}},
    ))
    assert code == ERR_VALIDATION, (
        f'{_OVER_INPUT!r} (39 significant digits) must be rejected with {ERR_VALIDATION}; got {code}'
    )
    assert message == "1 validation error detected: Attempting to store more than 38 significant digits in a Number", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    leaked = ddb.get_item(TableName=t, Key={'pk': {'S': 'over'}}, ConsistentRead=True)
    assert 'Item' not in leaked, (
        f'a rejected precision-overflow PutItem must not create the item, found {leaked.get("Item")}'
    )

    # --- same precision overflow inside an NS member, in exponent form ---
    code, message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'over-ns'}, 'ns': {'NS': [_OK_INPUT, _OVER_INPUT]}},
    ))
    assert code == ERR_VALIDATION, (
        f'a 39-significant-digit NS member in exponent form must be {ERR_VALIDATION}; got {code}'
    )
    assert message == "1 validation error detected: Attempting to store more than 38 significant digits in a Number", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    leaked_ns = ddb.get_item(TableName=t, Key={'pk': {'S': 'over-ns'}}, ConsistentRead=True)
    assert 'Item' not in leaked_ns, (
        f'a rejected NS write must not create the item, found {leaked_ns.get("Item")}'
    )

    # Control still works after the rejections.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'control'}, 'v': {'N': '42'}})
    control = ddb.get_item(TableName=t, Key={'pk': {'S': 'control'}}, ConsistentRead=True)['Item']
    assert control['v'] == {'N': '42'}, f'control write must still succeed, got {control}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
