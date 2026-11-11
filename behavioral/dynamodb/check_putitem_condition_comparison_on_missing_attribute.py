"""putitem-condition-comparison-on-missing-attribute."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-comparison-on-missing-attribute"
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression comparing a missing attribute: '=' treats it as absent
    and fails with ConditionalCheckFailedException; '<>', alone or OR'd with '<' against a
    second missing attribute, treats it as not-equal and the write applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddb-missattr-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    # The item exists but never carries the "seen" attribute: it is missing, not null.
    key_eq = {'pk': {'S': 'eq-target'}}
    ddb.put_item(TableName=table, Item=key_eq)

    # Negative: '=' against a missing attribute is false, so the write is refused.
    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**key_eq, 'seen': {'BOOL': True}},
            ConditionExpression='seen = :v',
            ExpressionAttributeValues={':v': {'BOOL': True}},
        ),
        *_CCF,
    )
    unchanged = ddb.get_item(TableName=table, Key=key_eq, ConsistentRead=True).get('Item')
    assert unchanged == {'pk': {'S': 'eq-target'}}, (
        f"PutItem rejected under 'seen = :v' must leave the item unchanged, got {unchanged!r}"
    )

    # Positive control, same missing attribute: '<>' treats it as not-equal, so the write applies.
    ne_item = {**key_eq, 'seen': {'BOOL': True}}
    ddb.put_item(
        TableName=table, Item=ne_item,
        ConditionExpression='seen <> :v',
        ExpressionAttributeValues={':v': {'BOOL': False}},
    )
    landed = ddb.get_item(TableName=table, Key=key_eq, ConsistentRead=True).get('Item')
    assert landed == ne_item, f"PutItem under 'seen <> :v' on a missing attribute left {landed!r}"

    # A brand-new item (never put before): status and updated_at are both missing.
    key_or = {'pk': {'S': 'or-target'}}
    or_item = {**key_or, 'status': {'S': 'new'}}
    ddb.put_item(
        TableName=table, Item=or_item,
        ConditionExpression='#s <> :v OR #u < :t',
        ExpressionAttributeNames={'#s': 'status', '#u': 'updated_at'},
        ExpressionAttributeValues={':v': {'S': 'retired'}, ':t': {'N': '100'}},
    )
    or_landed = ddb.get_item(TableName=table, Key=key_or, ConsistentRead=True).get('Item')
    assert or_landed == or_item, (
        f"PutItem under '#s <> :v OR #u < :t' against two missing attributes left {or_landed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
