"""item-size-limit-enforced-at-400kb."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "item-size-limit-enforced-at-400kb"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
KB = 1024


def _code(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises.

    An unexpected SUCCESS raises rather than returning None: a responder that ACCEPTS a request real
    AWS refuses is the strongest signal this check can produce.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An item of about 380 KB reads back byte-identical; an item over 400 KB in one attribute or across many, and an
    UpdateItem growing an item past it, raise ValidationException with the exact messages and change nothing.
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

    under = 380 * KB
    ddb.put_item(TableName=t, Item={'pk': {'S': 'under'}, 'blob': {'S': 'u' * under}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'under'}}, ConsistentRead=True).get('Item') or {}
    stored = got.get('blob', {}).get('S', '')
    assert len(stored) == under, f'a {under}-byte attribute must round-trip whole, got {len(stored)} bytes'
    assert stored == 'u' * under, 'the stored value must be byte-identical, not truncated or padded'

    over = 410 * KB
    code, message = _code(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'over'}, 'blob': {'S': 'o' * over}}))
    assert code == ERR_VALIDATION, f'a {over}-byte item exceeds the 400KB limit and must be {ERR_VALIDATION}, got {code!r}'
    assert message == "Item size has exceeded the maximum allowed size", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'over'}}, ConsistentRead=True), (
        'an item rejected for size must not be stored'
    )

    # The limit counts the whole item, not one attribute: many mid-sized
    # attributes that each pass individually still exceed the aggregate.
    spread = {f'a{i}': {'S': 'x' * (40 * KB)} for i in range(11)}
    spread['pk'] = {'S': 'spread'}
    code, message = _code(lambda: ddb.put_item(TableName=t, Item=spread))
    assert code == ERR_VALIDATION, (
        f'11 x 40KB attributes exceed 400KB in aggregate and must be {ERR_VALIDATION}, got {code!r}'
    )
    assert message == "Item size has exceeded the maximum allowed size", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'spread'}}, ConsistentRead=True), (
        'an item rejected for aggregate size must not be stored'
    )

    # The limit is enforced on the update path too: growing a stored item past
    # the aggregate bound is refused, and the item already stored is unchanged.
    grown = 390 * KB
    ddb.put_item(TableName=t, Item={'pk': {'S': 'grow'}, 'blob': {'S': 'g' * grown}})
    addition = 30 * KB
    code, message = _code(lambda: ddb.update_item(
        TableName=t,
        Key={'pk': {'S': 'grow'}},
        UpdateExpression='SET extra = :v',
        ExpressionAttributeValues={':v': {'S': 'x' * addition}},
    ))
    assert code == ERR_VALIDATION, (
        f'growing a {grown}-byte item by {addition} bytes exceeds the 400KB limit and must be '
        f'{ERR_VALIDATION}, got {code!r}'
    )
    assert message == "Item size to update has exceeded the maximum allowed size", (
        f"expected AWS's exact ValidationException message for the update path, got {message!r}"
    )
    untouched = ddb.get_item(TableName=t, Key={'pk': {'S': 'grow'}}, ConsistentRead=True).get('Item') or {}
    assert 'extra' not in untouched, (
        f'the refused UpdateItem SET must leave the existing item unchanged, got attribute '
        f'\'extra\' in {sorted(untouched)!r}'
    )
    assert untouched.get('blob', {}).get('S') == 'g' * grown, (
        "the existing item's stored attribute must be unaffected by the refused growth"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
