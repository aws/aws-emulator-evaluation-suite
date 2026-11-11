"""attribute-value-union-requires-exactly-one-member."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-value-union-requires-exactly-one-member"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


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


@tags("axis:rejection", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AttributeValue with zero members, with two members, or with an empty nested member fails with
    ValidationException and AWS's exact message, and none of those writes lands, while a one-member
    write succeeds."""
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

    # One member is the legal form, so the rejections below are about arity.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'control'}, 'a': {'S': 'one-member'}})
    assert ddb.get_item(TableName=t, Key={'pk': {'S': 'control'}}, ConsistentRead=True)['Item']['a'] == {'S': 'one-member'}, (
        'positive control failed: a single-member AttributeValue must round-trip'
    )

    zero, zero_message = _code(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'zero'}, 'bad': {}}))
    assert zero == ERR_VALIDATION, f'an AttributeValue with no member set must be {ERR_VALIDATION}, got {zero!r}'
    assert zero_message == "Supplied AttributeValue is empty, must contain exactly one of the supported datatypes", (
        f"expected AWS's exact ValidationException message, got {zero_message!r}"
    )

    two, two_message = _code(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'two'}, 'bad': {'S': 'x', 'N': '1'}}))
    assert two == ERR_VALIDATION, (
        f'an AttributeValue with two members set must be {ERR_VALIDATION} rather than silently '
        f'resolving to one of them, got {two!r}'
    )
    assert two_message == "Supplied AttributeValue has more than one datatypes set, must contain exactly one of the supported datatypes", (
        f"expected AWS's exact ValidationException message, got {two_message!r}"
    )

    for key in ('zero', 'two'):
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True)
        assert 'Item' not in got, f'rejected write {key!r} must leave no item behind, found {got.get("Item")!r}'

    # The nested case takes the same path: arity is a property of every
    # AttributeValue, not only of a top-level attribute.
    nested, nested_message = _code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'nested'}, 'm': {'M': {'inner': {}}}}
    ))
    assert nested == ERR_VALIDATION, (
        f'an empty AttributeValue nested inside a map must be {ERR_VALIDATION}, got {nested!r}'
    )
    assert nested_message == "Supplied AttributeValue is empty, must contain exactly one of the supported datatypes", (
        f"expected AWS's exact ValidationException message, got {nested_message!r}"
    )
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'nested'}}, ConsistentRead=True), (
        'rejected nested write must leave no item behind'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
