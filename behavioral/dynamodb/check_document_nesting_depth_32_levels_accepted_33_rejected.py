"""document-nesting-depth-32-levels-accepted-33-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "document-nesting-depth-32-levels-accepted-33-rejected"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

_LEAF = {'S': 'leaf'}


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


def _wrap_maps(levels: int, leaf: dict) -> dict:
    """`levels` nested M wrappers around `leaf`, so the document is `levels` + 1 deep."""
    value = leaf
    for _ in range(levels):
        value = {'M': {'n': value}}
    return value


def _wrap_lists(levels: int, leaf: dict) -> dict:
    """`levels` nested single-element L wrappers around `leaf`."""
    value = leaf
    for _ in range(levels):
        value = {'L': [value]}
    return value


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Document nesting is limited to 32 levels inclusive, for maps and lists alike.

    A 32-level item is stored and reads back intact to its leaf; a 33-level one is a
    ValidationException and nothing is written.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-nest-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- 32 levels (31 map wrappers + the scalar leaf): accepted and lossless ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'm32'}, 'd': _wrap_maps(31, _LEAF)})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'm32'}}, ConsistentRead=True).get('Item', {})
    value = got.get('d')
    assert value is not None, (
        f'a 32-level document is within the limit and must be readable, got attributes {sorted(got)!r}'
    )
    walked = 0
    while isinstance(value, dict) and 'M' in value:
        inner = value['M']
        assert sorted(inner) == ['n'], (
            f'at wrapper {walked} the stored map must carry exactly the authored key, got '
            f'{sorted(inner)!r}'
        )
        value = inner['n']
        walked += 1
    assert walked == 31, (
        f'a 32-level document must come back 32 levels deep: expected to unwrap 31 maps, unwrapped '
        f'{walked!r} before reaching {value!r}'
    )
    assert value == _LEAF, (
        f'the scalar at the bottom of a 32-level document must round-trip unchanged, got {value!r}'
    )

    # --- 33 levels via maps: refused, nothing lands ---
    code, message = _error_code(
        lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'm33'}, 'd': _wrap_maps(32, _LEAF)}),
        'PutItem with a 33-level chain of maps')
    assert code == ERR_VALIDATION, (
        f'a 33-level document exceeds the 32-level limit and must be refused {ERR_VALIDATION}, got '
        f'{code!r}'
    )
    assert message == "1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in the item have nested levels beyond supported limit", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    absent = ddb.get_item(TableName=t, Key={'pk': {'S': 'm33'}}, ConsistentRead=True)
    assert 'Item' not in absent, (
        f'the refused 33-level write must leave nothing behind -- not a truncated document -- got '
        f'{absent.get("Item")!r}'
    )

    # --- the same boundary reached through lists, not maps ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'l32'}, 'd': _wrap_lists(31, _LEAF)})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'l32'}}, ConsistentRead=True).get('Item', {})
    value = got.get('d')
    assert value is not None, (
        f'a 32-level chain of lists is within the limit and must be readable, got {sorted(got)!r}'
    )
    walked = 0
    while isinstance(value, dict) and 'L' in value:
        assert len(value['L']) == 1, (
            f'at wrapper {walked} the stored list must carry exactly the authored element, got '
            f'{len(value["L"])!r} elements'
        )
        value = value['L'][0]
        walked += 1
    assert walked == 31, (
        f'a 32-level chain of lists must come back 32 levels deep: unwrapped {walked!r} lists before '
        f'reaching {value!r}'
    )
    assert value == _LEAF, (
        f'the scalar at the bottom of a 32-level list chain must round-trip unchanged, got {value!r}'
    )

    code, message = _error_code(
        lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'l33'}, 'd': _wrap_lists(32, _LEAF)}),
        'PutItem with a 33-level chain of lists')
    assert code == ERR_VALIDATION, (
        f'a 33-level chain of lists exceeds the same 32-level limit and must be refused '
        f'{ERR_VALIDATION}, got {code!r}'
    )
    assert message == "1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in the item have nested levels beyond supported limit", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    absent = ddb.get_item(TableName=t, Key={'pk': {'S': 'l33'}}, ConsistentRead=True)
    assert 'Item' not in absent, (
        f'the refused 33-level list write must leave nothing behind, got {absent.get("Item")!r}'
    )

    # --- the same boundary reached through an ExpressionAttributeValue on a PutItem condition ---
    code, message = _error_code(
        lambda: ddb.put_item(
            TableName=t,
            Item={'pk': {'S': 'cond33'}, 'd': _LEAF},
            ConditionExpression='attribute_not_exists(pk) OR :v = :v',
            ExpressionAttributeValues={':v': _wrap_maps(32, _LEAF)},
        ),
        'PutItem whose ConditionExpression carries a 33-level EAV')
    assert code == ERR_VALIDATION, (
        f'a 33-level value in a PutItem ConditionExpression exceeds the limit and must be refused '
        f'{ERR_VALIDATION}, got {code!r}'
    )
    assert message == "1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in the item have nested levels beyond supported limit", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    absent = ddb.get_item(TableName=t, Key={'pk': {'S': 'cond33'}}, ConsistentRead=True)
    assert 'Item' not in absent, (
        f'the refused condition-side 33-level write must leave nothing behind, got '
        f'{absent.get("Item")!r}'
    )

    # --- the same boundary reached through an ExpressionAttributeValue on an UpdateItem SET ---
    code, message = _error_code(
        lambda: ddb.update_item(
            TableName=t,
            Key={'pk': {'S': 'm32'}},
            UpdateExpression='SET e = :v',
            ExpressionAttributeValues={':v': _wrap_maps(32, _LEAF)},
        ),
        'UpdateItem SET with a 33-level EAV')
    assert code == ERR_VALIDATION, (
        f'a 33-level EAV in an UpdateItem SET exceeds the limit and must be refused '
        f'{ERR_VALIDATION}, got {code!r}'
    )
    assert message == "1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in the item have nested levels beyond supported limit", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    untouched = ddb.get_item(TableName=t, Key={'pk': {'S': 'm32'}}, ConsistentRead=True).get('Item', {})
    assert 'e' not in untouched, (
        f'the refused UpdateItem SET must leave the existing item unchanged, got attribute \'e\' in '
        f'{sorted(untouched)!r}'
    )
    assert untouched.get('d') == _wrap_maps(31, _LEAF), (
        f"the existing item's other attribute must be unaffected by the refused update, got "
        f"{untouched.get('d')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
