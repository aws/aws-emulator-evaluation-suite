"""write-condition-parenthesized-forms-evaluate-like-unparenthesized."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "write-condition-parenthesized-forms-evaluate-like-unparenthesized"
GROUP = 'conditions'
SERVICES = ['dynamodb']
_CCF = ('ConditionalCheckFailedException', 'The conditional request failed')


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message)."""
    got = _error(fn)
    assert got == (code, message), f'expected {(code, message)!r}, got {got!r}'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parenthesised ConditionExpression on PutItem, DeleteItem and UpdateItem evaluates
    like the unparenthesised form, accepting a true condition and rejecting a false one
    with ConditionalCheckFailedException while leaving the item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddb-parens-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    # --- PutItem: per-condition form "(a) AND (b)" ---
    key_put = {'pk': {'S': 'item-put'}}
    base_put = {**key_put, 'ver': {'N': '1'}, 'status': {'S': 'A'}}
    ddb.put_item(TableName=table, Item=base_put)

    wrong_put = {**base_put, 'touched': {'S': 'should-not-land'}}
    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item=wrong_put,
            ConditionExpression='(ver = :v) AND (#st = :s)',
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={':v': {'N': '99'}, ':s': {'S': 'A'}},
        ),
        *_CCF,
    )
    unchanged = ddb.get_item(TableName=table, Key=key_put, ConsistentRead=True).get('Item')
    assert unchanged == base_put, f'PutItem under a false parenthesised condition changed the item to {unchanged!r}'

    right_put = {**base_put, 'touched': {'S': 'yes'}}
    ddb.put_item(
        TableName=table, Item=right_put,
        ConditionExpression='(ver = :v) AND (#st = :s)',
        ExpressionAttributeNames={'#st': 'status'},
        ExpressionAttributeValues={':v': {'N': '1'}, ':s': {'S': 'A'}},
    )
    landed = ddb.get_item(TableName=table, Key=key_put, ConsistentRead=True).get('Item')
    assert landed == right_put, f'PutItem under a true parenthesised condition left {landed!r}, expected {right_put!r}'

    # --- DeleteItem: full-wrap form "(a AND b)" ---
    key_del = {'pk': {'S': 'item-del'}}
    base_del = {**key_del, 'ver': {'N': '1'}, 'status': {'S': 'A'}}
    ddb.put_item(TableName=table, Item=base_del)

    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=key_del,
            ConditionExpression='(ver = :v AND #st = :s)',
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={':v': {'N': '99'}, ':s': {'S': 'A'}},
        ),
        *_CCF,
    )
    still_there = ddb.get_item(TableName=table, Key=key_del, ConsistentRead=True).get('Item')
    assert still_there == base_del, f'DeleteItem under a false parenthesised condition changed the item to {still_there!r}'

    ddb.delete_item(
        TableName=table, Key=key_del,
        ConditionExpression='(ver = :v AND #st = :s)',
        ExpressionAttributeNames={'#st': 'status'},
        ExpressionAttributeValues={':v': {'N': '1'}, ':s': {'S': 'A'}},
    )
    gone = ddb.get_item(TableName=table, Key=key_del, ConsistentRead=True).get('Item')
    assert gone is None, f'DeleteItem under a true parenthesised condition left {gone!r}'

    # --- UpdateItem: nested non-redundant form "a AND (b)" ---
    key_upd = {'pk': {'S': 'item-upd'}}
    base_upd = {**key_upd, 'ver': {'N': '1'}, 'status': {'S': 'A'}}
    ddb.put_item(TableName=table, Item=base_upd)

    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key_upd,
            UpdateExpression='SET #st = :ns',
            ExpressionAttributeNames={'#st': 'status'},
            ConditionExpression='ver = :v AND (#st = :s)',
            ExpressionAttributeValues={':v': {'N': '99'}, ':s': {'S': 'A'}, ':ns': {'S': 'B'}},
        ),
        *_CCF,
    )
    not_updated = ddb.get_item(TableName=table, Key=key_upd, ConsistentRead=True).get('Item')
    assert not_updated == base_upd, f'UpdateItem under a false parenthesised condition changed the item to {not_updated!r}'

    ddb.update_item(
        TableName=table, Key=key_upd,
        UpdateExpression='SET #st = :ns',
        ExpressionAttributeNames={'#st': 'status'},
        ConditionExpression='ver = :v AND (#st = :s)',
        ExpressionAttributeValues={':v': {'N': '1'}, ':s': {'S': 'A'}, ':ns': {'S': 'B'}},
    )
    updated = ddb.get_item(TableName=table, Key=key_upd, ConsistentRead=True).get('Item')
    assert updated == {**key_upd, 'ver': {'N': '1'}, 'status': {'S': 'B'}}, (
        f'UpdateItem under a true parenthesised condition left {updated!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
