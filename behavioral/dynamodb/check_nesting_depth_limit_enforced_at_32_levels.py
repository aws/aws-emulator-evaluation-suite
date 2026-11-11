"""nesting-depth-limit-enforced-at-32-levels."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nesting-depth-limit-enforced-at-32-levels"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _nest(levels: int):
    """A chain of `levels` maps around one scalar leaf, `levels + 1` levels deep in total."""
    value = {'S': 'leaf'}
    for _ in range(levels):
        value = {'M': {'k': value}}
    return value


def _code(fn) -> tuple[str, str]:
    """Return fn()'s error code and message; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 32-level attribute value is accepted and reads back at full depth; a 33-level map or list
    chain is rejected with ValidationException and the rejected map item is not stored."""
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

    # 31 wrapping maps + the leaf = 32 levels, the deepest accepted document.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'deepest'}, 'v': _nest(31)})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'deepest'}}, ConsistentRead=True).get('Item') or {}
    cursor = got.get('v')
    for level in range(31):
        assert cursor is not None and 'M' in cursor, (
            f'stored document must preserve all 31 map levels; level {level} was {cursor!r}'
        )
        cursor = cursor['M'].get('k')
    assert cursor == {'S': 'leaf'}, f'the leaf at depth 32 must round-trip, got {cursor!r}'

    # One level deeper is 33 and must be refused.
    code, message = _code(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'too-deep'}, 'v': _nest(32)}))
    assert code == ERR_VALIDATION, f'a 33-level document must be {ERR_VALIDATION}, got {code!r}'
    assert message == "1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in the item have nested levels beyond supported limit", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'too-deep'}}, ConsistentRead=True), (
        'a document rejected for nesting depth must not be stored'
    )

    # Lists count toward depth the same way maps do.
    deep_list = {'S': 'leaf'}
    for _ in range(32):
        deep_list = {'L': [deep_list]}
    code, message = _code(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'deep-list'}, 'v': deep_list}))
    assert code == ERR_VALIDATION, f'a 33-level list chain must be {ERR_VALIDATION}, got {code!r}'
    assert message == "1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in the item have nested levels beyond supported limit", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
