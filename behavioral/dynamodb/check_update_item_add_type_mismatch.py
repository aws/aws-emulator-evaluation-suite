"""update-item-add-type-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-type-mismatch"
GROUP = 'expressions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected {ERR_VALIDATION}, but the call SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD of a number onto a String attribute is rejected with ValidationException "An operand in the update
    expression has an incorrect data type" and leaves both attributes unchanged, while ADD onto a Number
    attribute applies (counter reads 15).
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {'pk': {'S': 'type-mismatch-1'}}
    ddb.put_item(TableName=t, Item={**key, 'tag': {'S': 'not-a-number'}, 'counter': {'N': '10'}})

    # Positive control: ADD on a Number attribute succeeds -- without this, a target that
    # rejects every ADD call would be indistinguishable from one that correctly rejects only
    # the type mismatch.
    ddb.update_item(
        TableName=t,
        Key=key,
        UpdateExpression='ADD #c :delta',
        ExpressionAttributeNames={'#c': 'counter'},
        ExpressionAttributeValues={':delta': {'N': '5'}},
    )
    controlled = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert controlled['counter'] == {'N': '15'}, f"positive control ADD did not apply, got {controlled.get('counter')}"

    code, message = _error_code(
        lambda: ddb.update_item(
            TableName=t,
            Key=key,
            UpdateExpression='ADD tag :delta',
            ExpressionAttributeValues={':delta': {'N': '5'}},
        )
    )
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}'
    assert message == "An operand in the update expression has an incorrect data type", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    unchanged = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert unchanged['tag'] == {'S': 'not-a-number'}, (
        'rejected ADD must leave the attribute type/value untouched'
    )
    assert unchanged['counter'] == {'N': '15'}, (
        'rejected ADD on one attribute must not affect a sibling attribute'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
