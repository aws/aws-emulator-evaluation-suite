"""condition-expression-contains-same-path-and-between-reversed-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-expression-contains-same-path-and-between-reversed-rejected"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """contains(path, path) and a BETWEEN with its bounds reversed are rejected by
    ConditionExpression parsing itself, not by the conditional check, and leave the
    existing item untouched.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(
        TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30},
    )
    ddb.put_item(
        TableName=table,
        Item={'pk': {'S': 'item'}, 'tagset': {'SS': ['a', 'b']}, 'score': {'N': '5'}},
    )

    def read():
        item = ddb.get_item(TableName=table, Key={'pk': {'S': 'item'}}, ConsistentRead=True)['Item']
        # DynamoDB does not guarantee the member order of a returned set, so normalize
        # the SS attribute to a frozenset before any equality comparison.
        item['tagset'] = {'SS': frozenset(item['tagset']['SS'])}
        return item

    def update(update_expr, cond_expr, values):
        ddb.update_item(
            TableName=table, Key={'pk': {'S': 'item'}}, UpdateExpression=update_expr,
            ConditionExpression=cond_expr, ExpressionAttributeValues=values,
        )

    def rejected_update(update_expr, cond_expr, values):
        """The (Code, Message) of an update real AWS refuses. RAISES on unexpected success."""
        try:
            update(update_expr, cond_expr, values)
        except ClientError as exc:
            err = exc.response.get('Error', {})
            return err.get('Code'), err.get('Message')
        raise AssertionError(f'real AWS refuses the update conditioned on {cond_expr!r}, but it SUCCEEDED')

    baseline = read()

    # contains(path, path): the two operands name the same attribute, which the
    # function rejects while parsing the expression, before any item is examined.
    code, message = rejected_update(
        'SET score = :nv', 'contains(tagset, tagset)', {':nv': {'N': '999'}},
    )
    assert code == ERR_VALIDATION, f"contains(tagset, tagset) should be {ERR_VALIDATION}, got {code!r}"
    assert code != ERR_CONDITIONAL_CHECK_FAILED, (
        "a same-path contains() is a parse-time defect, never a conditional-check failure"
    )
    assert message == (
        '1 validation error detected: Invalid ConditionExpression: The first operand must be '
        'distinct from the remaining operands for this operator or function; operator: contains, '
        'first operand: [tagset]'
    ), f"unexpected message for same-path contains(): {message!r}"
    got = read()
    assert got == baseline, f"item must be unchanged after the rejected contains() update, got {got!r}"

    # BETWEEN whose lower bound is numerically above its upper bound: rejected by the
    # BETWEEN operator's own bound check, before any item is examined.
    code, message = rejected_update(
        'SET score = :nv', 'score BETWEEN :hi AND :lo',
        {':nv': {'N': '888'}, ':hi': {'N': '100'}, ':lo': {'N': '1'}},
    )
    assert code == ERR_VALIDATION, f"BETWEEN with lower>upper should be {ERR_VALIDATION}, got {code!r}"
    assert code != ERR_CONDITIONAL_CHECK_FAILED, (
        "a reversed BETWEEN is a parse-time defect, never a conditional-check failure"
    )
    assert message == (
        '1 validation error detected: Invalid ConditionExpression: The BETWEEN operator requires '
        'upper bound to be greater than or equal to lower bound; lower bound operand: '
        'AttributeValue: {N:100}, upper bound operand: AttributeValue: {N:1}'
    ), f"unexpected message for reversed BETWEEN: {message!r}"
    got = read()
    assert got == baseline, f"item must be unchanged after the rejected BETWEEN update, got {got!r}"

    # Positive control: contains() on two distinct attributes, and a correctly ordered
    # BETWEEN, both parse and admit the write — the item is not simply frozen.
    update(
        'SET tagset = :nv', 'contains(tagset, :member) AND score BETWEEN :lo AND :hi',
        {':nv': {'SS': ['a', 'b', 'c']}, ':member': {'S': 'a'}, ':lo': {'N': '1'}, ':hi': {'N': '100'}},
    )
    got = read()
    assert got['tagset'] == {'SS': frozenset({'a', 'b', 'c'})}, (
        f"the positive-control update should have admitted the write, got {got.get('tagset')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
