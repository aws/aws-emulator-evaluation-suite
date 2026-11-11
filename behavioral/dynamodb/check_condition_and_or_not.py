"""condition-and-or-not."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-and-or-not"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'
ERR_CONDITIONAL_CHECK_FAILED_MESSAGE = 'The conditional request failed'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConditionExpression AND/OR/NOT each admit a true combination and reject a false one."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'logic'}, 'a': {'N': '5'}, 'b': {'N': '10'}})

    def read():
        return ddb.get_item(TableName=table, Key={'pk': {'S': 'logic'}}, ConsistentRead=True).get('Item')

    def update(update_expr, cond_expr, values):
        ddb.update_item(TableName=table, Key={'pk': {'S': 'logic'}}, UpdateExpression=update_expr, ConditionExpression=cond_expr, ExpressionAttributeValues=values)

    def rejected_update(update_expr, cond_expr, values):
        """The (Code, Message) of an update real AWS refuses. RAISES on unexpected success."""
        try:
            update(update_expr, cond_expr, values)
        except ClientError as exc:
            err = exc.response.get('Error', {})
            return err.get('Code'), err.get('Message')
        raise AssertionError(f'real AWS refuses the update conditioned on {cond_expr!r}, but it SUCCEEDED')

    # AND: true-true is admitted; true-false is rejected and leaves the field untouched.
    update('SET c_and = :v', 'a < :ten AND b > :five', {':v': {'S': 'pos-and'}, ':ten': {'N': '10'}, ':five': {'N': '5'}})
    got = read()
    assert got['c_and'] == {'S': 'pos-and'}, f"expected c_and=pos-and after AND true-true, got {got.get('c_and')!r}"

    code, message = rejected_update('SET c_and = :v', 'a < :ten AND b > :fifteen', {':v': {'S': 'neg-and'}, ':ten': {'N': '10'}, ':fifteen': {'N': '15'}})
    assert code == ERR_CONDITIONAL_CHECK_FAILED, f"AND true-false update should be rejected with {ERR_CONDITIONAL_CHECK_FAILED}, got {code!r}"
    assert message == ERR_CONDITIONAL_CHECK_FAILED_MESSAGE, f"expected {ERR_CONDITIONAL_CHECK_FAILED_MESSAGE!r}, got {message!r}"
    got = read()
    assert got['c_and'] == {'S': 'pos-and'}, f"c_and must be unchanged by the rejected AND update, got {got.get('c_and')!r}"

    # OR: false-true is admitted; false-false is rejected and leaves the field untouched.
    update('SET c_or = :v', 'a > :hundred OR b > :five', {':v': {'S': 'pos-or'}, ':hundred': {'N': '100'}, ':five': {'N': '5'}})
    got = read()
    assert got['c_or'] == {'S': 'pos-or'}, f"expected c_or=pos-or after OR false-true, got {got.get('c_or')!r}"

    code, message = rejected_update('SET c_or = :v', 'a > :hundred OR b > :fifteen', {':v': {'S': 'neg-or'}, ':hundred': {'N': '100'}, ':fifteen': {'N': '15'}})
    assert code == ERR_CONDITIONAL_CHECK_FAILED, f"OR false-false update should be rejected with {ERR_CONDITIONAL_CHECK_FAILED}, got {code!r}"
    assert message == ERR_CONDITIONAL_CHECK_FAILED_MESSAGE, f"expected {ERR_CONDITIONAL_CHECK_FAILED_MESSAGE!r}, got {message!r}"
    got = read()
    assert got['c_or'] == {'S': 'pos-or'}, f"c_or must be unchanged by the rejected OR update, got {got.get('c_or')!r}"

    # NOT: negates its operand — NOT(false) is admitted, NOT(true) is rejected.
    update('SET c_not = :v', 'NOT (a > :hundred)', {':v': {'S': 'pos-not'}, ':hundred': {'N': '100'}})
    got = read()
    assert got['c_not'] == {'S': 'pos-not'}, f"expected c_not=pos-not after NOT false, got {got.get('c_not')!r}"

    code, message = rejected_update('SET c_not = :v', 'NOT (a < :hundred)', {':v': {'S': 'neg-not'}, ':hundred': {'N': '100'}})
    assert code == ERR_CONDITIONAL_CHECK_FAILED, f"NOT true update should be rejected with {ERR_CONDITIONAL_CHECK_FAILED}, got {code!r}"
    assert message == ERR_CONDITIONAL_CHECK_FAILED_MESSAGE, f"expected {ERR_CONDITIONAL_CHECK_FAILED_MESSAGE!r}, got {message!r}"
    got = read()
    assert got['c_not'] == {'S': 'pos-not'}, f"c_not must be unchanged by the rejected NOT update, got {got.get('c_not')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
