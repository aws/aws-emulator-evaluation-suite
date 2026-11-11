"""nesting-depth-error-precedence-across-malformed-requests."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nesting-depth-error-precedence-across-malformed-requests"
GROUP = 'item-validation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_DEPTH = ('1 validation error detected: Nesting Levels have exceeded supported limits: '
             'Attributes in the item have nested levels beyond supported limit')


def _nest(levels: int):
    """A chain of `levels` maps around one scalar leaf, `levels + 1` levels deep in total."""
    value = {'S': 'leaf'}
    for _ in range(levels):
        value = {'M': {'k': value}}
    return value


def _code_and_message(fn):
    """fn()'s ValidationException (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


def _absent(ddb, table, key):
    return 'Item' not in ddb.get_item(TableName=table, Key={'pk': {'S': key}}, ConsistentRead=True)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A document 39 levels past the nesting limit still reports the nesting-limit error when
    paired with a bad ReturnValues or an empty expression attribute name, but a
    ConditionExpression syntax error or an unused expression value is masked by it instead.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-attributes
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

    deep = _nest(39)
    shallow = {'S': 'leaf'}

    # Positive control: the mechanism itself works for a well-formed call.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ctrl'}, 'doc': shallow})
    assert not _absent(ddb, table, 'ctrl'), 'the positive control write must be stored'

    # Invalid ReturnValues: the enum-constraint error wins whether or not the item is deep.
    msg_returnvalues = (
        '1 validation error detected: Failed to satisfy constraint: Member must satisfy '
        'enum value set: [ALL_OLD, UPDATED_OLD, ALL_NEW, UPDATE_NEW, NONE]'
    )
    for key, doc in (('a-combo', deep), ('a-solo', shallow)):
        code, message = _code_and_message(lambda doc=doc, key=key: ddb.put_item(
            TableName=table, Item={'pk': {'S': key}, 'doc': doc}, ReturnValues='BOGUS_VALUE'))
        assert code == ERR_VALIDATION, f'{key}: expected {ERR_VALIDATION}, got {code!r}'
        assert message == msg_returnvalues, f'{key}: unexpected message {message!r}'
        assert _absent(ddb, table, key), f'{key}: rejected put must not store the item'

    # Empty attribute name in ExpressionAttributeNames: also unaffected by depth.
    msg_empty_name = (
        '1 validation error detected: ExpressionAttributeNames contains invalid value: '
        'Empty attribute name for key #x'
    )
    for key, doc in (('b-combo', deep), ('b-solo', shallow)):
        code, message = _code_and_message(lambda doc=doc, key=key: ddb.update_item(
            TableName=table, Key={'pk': {'S': key}}, UpdateExpression='SET #x = :v',
            ExpressionAttributeNames={'#x': ''}, ExpressionAttributeValues={':v': doc}))
        assert code == ERR_VALIDATION, f'{key}: expected {ERR_VALIDATION}, got {code!r}'
        assert message == msg_empty_name, f'{key}: unexpected message {message!r}'
        assert _absent(ddb, table, key), f'{key}: rejected update must not create the item'

    # ConditionExpression syntax error: masked by the nesting error once the item is deep.
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'c-combo'}}, UpdateExpression='SET doc = :v',
        ConditionExpression='attribute_exists(', ExpressionAttributeValues={':v': deep}))
    assert code == ERR_VALIDATION, f'c-combo: expected {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_DEPTH, f'c-combo: expected the nesting-depth message, got {message!r}'
    assert _absent(ddb, table, 'c-combo'), 'c-combo: rejected update must not create the item'

    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'c-solo'}}, UpdateExpression='SET doc = :v',
        ConditionExpression='attribute_exists(', ExpressionAttributeValues={':v': shallow}))
    assert code == ERR_VALIDATION, f'c-solo: expected {ERR_VALIDATION}, got {code!r}'
    assert message == (
        '1 validation error detected: Invalid ConditionExpression: Syntax error; '
        'token: "<EOF>", near: "("'
    ), f'c-solo: unexpected message {message!r}'
    assert _absent(ddb, table, 'c-solo'), 'c-solo: rejected update must not create the item'

    # Unused ExpressionAttributeValue: also masked by the nesting error once the item is deep.
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'd-combo'}}, UpdateExpression='SET doc = :v',
        ExpressionAttributeValues={':v': deep, ':unused': {'S': 'x'}}))
    assert code == ERR_VALIDATION, f'd-combo: expected {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_DEPTH, f'd-combo: expected the nesting-depth message, got {message!r}'
    assert _absent(ddb, table, 'd-combo'), 'd-combo: rejected update must not create the item'

    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'd-solo'}}, UpdateExpression='SET doc = :v',
        ExpressionAttributeValues={':v': shallow, ':unused': {'S': 'x'}}))
    assert code == ERR_VALIDATION, f'd-solo: expected {ERR_VALIDATION}, got {code!r}'
    assert message == (
        '1 validation error detected: Value provided in ExpressionAttributeValues unused in '
        'expressions: keys: {:unused}'
    ), f'd-solo: unexpected message {message!r}'
    assert _absent(ddb, table, 'd-solo'), 'd-solo: rejected update must not create the item'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
