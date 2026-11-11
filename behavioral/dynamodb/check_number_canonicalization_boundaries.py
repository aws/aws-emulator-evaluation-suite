"""number-canonicalization-boundaries."""
from __future__ import annotations

from decimal import Decimal

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "number-canonicalization-boundaries"
GROUP = 'item_crud'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

# Documented DynamoDB Number range: 1E-130 .. 9.9999999999999999999999999999999999999E+125
# (and the mirrored negative interval). 38 digits of significand precision.
_MAX_MAGNITUDE = '9.9999999999999999999999999999999999999E+125'
_OVER_MAGNITUDE = '1E+126'
_THIRTY_EIGHT_DIGITS = '1.2345678901234567890123456789012345678'

# Accepted input form -> the canonical decimal STRING DynamoDB stores it as. A leading '+'
# on the mantissa is accepted and dropped; a bare leading or trailing '.' is accepted and
# filled; '-0' normalises to '0'; zero padding is stripped; exponents are folded out.
_CANONICAL_FORMS = [
    ('+7', '7'),
    ('+1.5', '1.5'),
    ('+0', '0'),
    ('-0', '0'),
    ('+0.0', '0'),
    ('+1e2', '100'),
    ('1e+2', '100'),
    ('1.5E+3', '1500'),
    ('+.5', '0.5'),
    ('.5', '0.5'),
    ('5.', '5'),
    ('1.e4', '10000'),
    ('00042', '42'),
    ('+1e-2', '0.01'),
    ('1.23E10', '12300000000'),
]

# Malformed mantissa/exponent forms, and any surrounding or embedded whitespace. Each is
# rejected: N is a string on the wire but a decimal in the data model, so the parse is
# strict and whitespace is never trimmed for the caller.
_MALFORMED_FORMS = [
    'e2', '+e2', '1e', '1e+', '++7', '+-7', '-+7',
    '1+2', '+1+2', '1.2.3', '+1.2.3', '1.2e3.4',
    '.', '+', '-', '0x5', 'NaN', 'Infinity', '1_000',
    ' 7', '7 ', '1 5', '1e1.5',
]

# A mantissa of zero does not exempt the magnitude check: the exponent alone still trips the
# documented overflow/underflow boundary, with the matching overflow/underflow message.
_ZERO_OVER = '0E+300'
_ZERO_UNDER = '0E-300'


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DynamoDB stores N values canonically (zeros trimmed, exponents folded, 38 digits kept) and reads them back by
    any spelling; a non-numeric string, magnitudes above 9.99...E+125 and an exponent below the 1E-130 floor raise
    ValidationException with the exact message and store nothing, while the 9.99...E+125 ceiling is accepted.
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

    # --- canonicalization: leading and trailing zeros are trimmed ---
    ddb.put_item(TableName=t, Item={
        'pk': {'S': 'canon'},
        'padded': {'N': '0100.50'},
        'neg_padded': {'N': '-0.500'},
        'zero': {'N': '0'},
        'exp': {'N': '1e3'},
        'precise': {'N': _THIRTY_EIGHT_DIGITS},
    })
    item = ddb.get_item(TableName=t, Key={'pk': {'S': 'canon'}}, ConsistentRead=True)['Item']

    assert item['padded'] == {'N': '100.5'}, (
        f'0100.50 must be stored canonically as 100.5 (leading and trailing zeros trimmed), '
        f'got {item["padded"]}'
    )
    assert item['neg_padded'] == {'N': '-0.5'}, (
        f'-0.500 must be stored canonically as -0.5, got {item["neg_padded"]}'
    )
    assert item['zero'] == {'N': '0'}, f'0 must round-trip as 0, got {item["zero"]}'
    # Exponent notation is folded into a plain decimal STRING, not merely into an equal
    # value. The stored form is what a client reads back and compares, so this asserts the
    # string: a value-only comparison (Decimal(..) == Decimal('1000')) is satisfied by an
    # implementation that echoes '1e3' straight back, which is exactly the echoing behaviour this
    # check exists to catch.
    assert item['exp'] == {'N': '1000'}, (
        f'exponent notation 1e3 must be stored as the canonical decimal string "1000", '
        f'got {item["exp"]}'
    )
    assert Decimal(item['precise']['N']) == Decimal(_THIRTY_EIGHT_DIGITS), (
        f'38 significant digits must round-trip without loss of precision, got {item["precise"]}'
    )

    # --- the full accepted-form table, asserted on the stored STRING ---
    # One representative value cannot separate "canonicalises" from "happens to echo a form
    # that was already canonical". Each form below differs from its canonical string in a
    # DIFFERENT way (sign prefix, bare leading/trailing dot, zero padding, exponent), so a
    # partial implementation fails on the specific form it does not handle.
    for raw, expected in _CANONICAL_FORMS:
        key = f'n-canon-{raw}'
        ddb.put_item(TableName=t, Item={'pk': {'S': key}, 'v': {'N': raw}})
        got = ddb.get_item(
            TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True,
        )['Item']['v']
        assert got == {'N': expected}, (
            f'N input {raw!r} must be stored as the canonical string {expected!r}, '
            f'got {got}'
        )

    # --- malformed mantissa/exponent forms and ANY whitespace are rejected ---
    for raw in _MALFORMED_FORMS:
        code, message = _error_code(lambda raw=raw: ddb.put_item(
            TableName=t, Item={'pk': {'S': 'n-malformed'}, 'v': {'N': raw}},
        ))
        assert code == ERR_VALIDATION, (
            f'malformed N input {raw!r} must be rejected with {ERR_VALIDATION}; got {code}'
        )
        assert message == f"1 validation error detected: The parameter cannot be converted to a numeric value: {raw}", (
            f"expected AWS's exact ValidationException message, got {message!r}"
        )
    # Effect absent: not one of the rejected writes created the item.
    leaked_malformed = ddb.get_item(
        TableName=t, Key={'pk': {'S': 'n-malformed'}}, ConsistentRead=True,
    )
    assert 'Item' not in leaked_malformed, (
        f'no rejected malformed-N write may create the item, found '
        f'{leaked_malformed.get("Item")}'
    )

    # --- canonical form is what key/comparison paths see ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'cmp'}, 'v': {'N': '01.10'}})
    matched = ddb.get_item(
        TableName=t, Key={'pk': {'S': 'cmp'}}, ConsistentRead=True,
    )['Item']
    assert matched['v'] == {'N': '1.1'}, f'01.10 must canonicalize to 1.1, got {matched["v"]}'
    # A ConditionExpression written against the CANONICAL value must match.
    ddb.put_item(
        TableName=t,
        Item={'pk': {'S': 'cmp'}, 'v': {'N': '2'}},
        ConditionExpression='v = :old',
        ExpressionAttributeValues={':old': {'N': '1.1'}},
    )

    # --- boundary control: the maximum documented magnitude is ACCEPTED ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'n-max'}, 'v': {'N': _MAX_MAGNITUDE}})
    at_max = ddb.get_item(TableName=t, Key={'pk': {'S': 'n-max'}}, ConsistentRead=True)['Item']
    assert Decimal(at_max['v']['N']) == Decimal(_MAX_MAGNITUDE), (
        f'the documented maximum N magnitude must be accepted and round-trip, got {at_max["v"]}'
    )

    # --- rejection: one magnitude step past the ceiling ---
    code, message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'n-oob'}, 'v': {'N': _OVER_MAGNITUDE}},
    ))
    assert code == ERR_VALIDATION, (
        f'N magnitude {_OVER_MAGNITUDE} is past the documented ceiling and must be rejected with '
        f'{ERR_VALIDATION}; got {code}'
    )
    assert message == "1 validation error detected: Number overflow. Attempting to store a number with magnitude larger than supported range", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    # Effect absent: the rejected write created nothing.
    leaked = ddb.get_item(TableName=t, Key={'pk': {'S': 'n-oob'}}, ConsistentRead=True)
    assert 'Item' not in leaked, (
        f'a rejected out-of-range PutItem must not create the item, found {leaked.get("Item")}'
    )
    # The negative mirror of the range is enforced too.
    neg_code, neg_message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'n-oob-neg'}, 'v': {'N': '-' + _OVER_MAGNITUDE}},
    ))
    assert neg_code == ERR_VALIDATION, (
        f'N magnitude -{_OVER_MAGNITUDE} must also be rejected with {ERR_VALIDATION}; got {neg_code}'
    )
    assert neg_message == "1 validation error detected: Number overflow. Attempting to store a number with magnitude larger than supported range", (
        f"expected AWS's exact ValidationException message, got {neg_message!r}"
    )

    # --- a zero mantissa does not exempt the magnitude check: the exponent alone trips it ---
    over_code, over_message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'n-zero-over'}, 'v': {'N': _ZERO_OVER}},
    ))
    assert over_code == ERR_VALIDATION, (
        f'{_ZERO_OVER} has a zero mantissa but an out-of-range exponent and must be rejected with '
        f'{ERR_VALIDATION}; got {over_code}'
    )
    assert over_message == "1 validation error detected: Number overflow. Attempting to store a number with magnitude larger than supported range", (
        f"expected AWS's exact ValidationException message, got {over_message!r}"
    )
    leaked_zero_over = ddb.get_item(TableName=t, Key={'pk': {'S': 'n-zero-over'}}, ConsistentRead=True)
    assert 'Item' not in leaked_zero_over, (
        f'a rejected {_ZERO_OVER} PutItem must not create the item, found {leaked_zero_over.get("Item")}'
    )

    under_code, under_message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'n-zero-under'}, 'v': {'N': _ZERO_UNDER}},
    ))
    assert under_code == ERR_VALIDATION, (
        f'{_ZERO_UNDER} has a zero mantissa but an out-of-range exponent and must be rejected with '
        f'{ERR_VALIDATION}; got {under_code}'
    )
    assert under_message == "1 validation error detected: Number underflow. Attempting to store a number with magnitude smaller than supported range", (
        f"expected AWS's exact ValidationException message, got {under_message!r}"
    )
    leaked_zero_under = ddb.get_item(TableName=t, Key={'pk': {'S': 'n-zero-under'}}, ConsistentRead=True)
    assert 'Item' not in leaked_zero_under, (
        f'a rejected {_ZERO_UNDER} PutItem must not create the item, found {leaked_zero_under.get("Item")}'
    )

    # Control still works after the rejections.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'n-ok'}, 'v': {'N': '42'}})
    ok = ddb.get_item(TableName=t, Key={'pk': {'S': 'n-ok'}}, ConsistentRead=True)['Item']
    assert ok['v'] == {'N': '42'}, f'control write must still succeed, got {ok}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
