"""put-and-delete-item-reject-return-values-all-new."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-and-delete-item-reject-return-values-all-new"
GROUP = 'negative-classes'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
# The ReturnValue enum is shared by four operations, but PutItem and DeleteItem accept only two of
# its members. The other three are individually valid enum values and wrong for these operations.
_REFUSED = ('ALL_NEW', 'UPDATED_OLD', 'UPDATED_NEW')


def _code(fn):
    """The (code, message) *fn* raises; raises AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PutItem and DeleteItem refuse ReturnValues ALL_NEW, UPDATED_OLD and UPDATED_NEW with
    ValidationException and leave the item untouched, while UpdateItem accepts ALL_NEW.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-retvals-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    original = {'pk': {'S': 'item'}, 'body': {'S': 'original'}}
    ddb.put_item(TableName=table, Item=original)

    def _current():
        return ddb.get_item(
            TableName=table, Key={'pk': {'S': 'item'}}, ConsistentRead=True,
        ).get('Item')

    # --- PutItem refuses the three members it does not accept ---
    for value in _REFUSED:
        code, message = _code(lambda v=value: ddb.put_item(
            TableName=table,
            Item={'pk': {'S': 'item'}, 'body': {'S': 'overwritten'}},
            ReturnValues=v,
        ))
        assert code == ERR_VALIDATION, (
            f'PutItem accepts only NONE and ALL_OLD for ReturnValues, so {value!r} must be refused '
            f'with {ERR_VALIDATION}; got {code}'
        )
        assert message == "1 validation error detected: ReturnValues can only be ALL_OLD or NONE", (
            f"expected AWS's exact ValidationException message, got {message!r}"
        )
        assert _current() == original, (
            f'a PutItem refused for ReturnValues={value!r} must not have written its item: expected '
            f'{original!r} still stored, found {_current()!r}'
        )

    # --- DeleteItem refuses the same three, and deletes nothing when it does ---
    for value in _REFUSED:
        code, message = _code(lambda v=value: ddb.delete_item(
            TableName=table, Key={'pk': {'S': 'item'}}, ReturnValues=v,
        ))
        assert code == ERR_VALIDATION, (
            f'DeleteItem accepts only NONE and ALL_OLD for ReturnValues, so {value!r} must be '
            f'refused with {ERR_VALIDATION}; got {code}'
        )
        assert message == "1 validation error detected: ReturnValues can only be ALL_OLD or NONE", (
            f"expected AWS's exact ValidationException message, got {message!r}"
        )
        assert _current() == original, (
            f'a DeleteItem refused for ReturnValues={value!r} must not have removed the item: '
            f'expected {original!r} still stored, found {_current()!r}'
        )

    # --- control: UpdateItem accepts what PutItem refuses ---
    updated = ddb.update_item(
        TableName=table,
        Key={'pk': {'S': 'item'}},
        UpdateExpression='SET body = :b',
        ExpressionAttributeValues={':b': {'S': 'updated'}},
        ReturnValues='ALL_NEW',
    )
    assert updated.get('Attributes') == {'pk': {'S': 'item'}, 'body': {'S': 'updated'}}, (
        f'UpdateItem does accept ALL_NEW and must return the whole item as it now stands, got '
        f'{updated.get("Attributes")!r}'
    )

    # --- control: the values PutItem and DeleteItem DO accept still work ---
    replaced = ddb.put_item(
        TableName=table,
        Item={'pk': {'S': 'item'}, 'body': {'S': 'replaced'}},
        ReturnValues='ALL_OLD',
    )
    assert replaced.get('Attributes') == {'pk': {'S': 'item'}, 'body': {'S': 'updated'}}, (
        f'PutItem with ReturnValues=ALL_OLD must return the item as it was before the write, got '
        f'{replaced.get("Attributes")!r}'
    )
    removed = ddb.delete_item(
        TableName=table, Key={'pk': {'S': 'item'}}, ReturnValues='ALL_OLD',
    )
    assert removed.get('Attributes') == {'pk': {'S': 'item'}, 'body': {'S': 'replaced'}}, (
        f'DeleteItem with ReturnValues=ALL_OLD must return the item it removed, got '
        f'{removed.get("Attributes")!r}'
    )
    assert _current() is None, f'the item must be gone after the accepted delete, found {_current()!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
