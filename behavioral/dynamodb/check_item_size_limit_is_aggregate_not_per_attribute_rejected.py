"""item-size-limit-is-aggregate-not-per-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "item-size-limit-is-aggregate-not-per-attribute-rejected"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

_KB = 1024


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The 400 KB item limit is an aggregate: a ~380 KB item round-trips intact and nine 40 KB
    attributes are accepted, while a ~410 KB attribute or eleven 40 KB attributes are refused
    ValidationException with AWS's message and store nothing."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-size-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- under the ceiling: accepted AND lossless ---
    under = 'x' * (380 * _KB)
    ddb.put_item(TableName=t, Item={'pk': {'S': 'under'}, 'd': {'S': under}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'under'}}, ConsistentRead=True).get('Item', {})
    stored = got.get('d', {}).get('S')
    assert stored is not None, f'a ~380KB item is under the ceiling and must be readable, got {got.keys()!r}'
    assert len(stored) == len(under), (
        f'a ~380KB value must be stored at its full length {len(under)!r}, got {len(stored)!r} -- '
        f'the store truncated it'
    )
    assert stored == under, (
        'a ~380KB value must read back byte-identical; the returned value has the right length but '
        'different content'
    )

    # --- over the ceiling in one attribute: refused, and nothing lands ---
    over = 'x' * (410 * _KB)
    code, message = _error_code(
        lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'over'}, 'd': {'S': over}}),
        'PutItem with a single ~410KB attribute')
    assert code == ERR_VALIDATION, (
        f'a ~410KB item exceeds the 400KB ceiling and must be refused {ERR_VALIDATION}, got {code!r}'
    )
    assert message == "Item size has exceeded the maximum allowed size", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    absent = ddb.get_item(TableName=t, Key={'pk': {'S': 'over'}}, ConsistentRead=True)
    assert 'Item' not in absent, (
        f'the refused ~410KB write must leave nothing behind, got {absent.get("Item")!r}'
    )

    # --- over the ceiling in aggregate, with every single attribute far below it ---
    chunk = 'y' * (40 * _KB)
    many = {'pk': {'S': 'many'}}
    for i in range(11):
        many[f'a{i}'] = {'S': chunk}
    code, message = _error_code(lambda: ddb.put_item(TableName=t, Item=many),
                       'PutItem with eleven 40KB attributes')
    assert code == ERR_VALIDATION, (
        f'eleven 40KB attributes are ~440KB in aggregate and must be refused {ERR_VALIDATION} even '
        f'though no single attribute is near the ceiling, got {code!r}'
    )
    assert message == "Item size has exceeded the maximum allowed size", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    absent = ddb.get_item(TableName=t, Key={'pk': {'S': 'many'}}, ConsistentRead=True)
    assert 'Item' not in absent, (
        f'the refused 11x40KB write must leave nothing behind -- not even a partial item -- got '
        f'{absent.get("Item")!r}'
    )

    # Control: without it the 11-attribute rejection is also consistent with a per-attribute limit.
    few = {'pk': {'S': 'few'}}
    for i in range(9):
        few[f'a{i}'] = {'S': chunk}
    ddb.put_item(TableName=t, Item=few)
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'few'}}, ConsistentRead=True).get('Item', {})
    assert sorted(got) == ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'pk'], (
        f'nine 40KB attributes are ~360KB in aggregate and must all be accepted and readable, got '
        f'{sorted(got)!r}'
    )
    assert all(got[f'a{i}'] == {'S': chunk} for i in range(9)), (
        'every one of the nine accepted 40KB attributes must read back intact'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
