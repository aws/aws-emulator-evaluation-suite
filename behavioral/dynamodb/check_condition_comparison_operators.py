"""condition-comparison-operators."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-comparison-operators"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'
ERR_CONDITIONAL_CHECK_FAILED_MESSAGE = 'The conditional request failed'


def _read(ddb, table, pk):
    resp = ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True)
    return resp['Item']


def _update(ddb, table, pk, new_val, op, threshold):
    ddb.update_item(
        TableName=table,
        Key={'pk': {'S': pk}},
        UpdateExpression='SET val = :new',
        ConditionExpression=f'val {op} :threshold',
        ExpressionAttributeValues={':new': {'N': new_val}, ':threshold': {'N': threshold}},
    )


def _rejected_update(ddb, table, pk, new_val, op, threshold):
    """The (Code, Message) of an update real AWS refuses. RAISES on unexpected success."""
    try:
        _update(ddb, table, pk, new_val, op, threshold)
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS refuses the update conditioned on val {op} {threshold}, but it SUCCEEDED')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every ConditionExpression comparison operator (<, <=, >, >=, =, <>) admits a true
    condition and rejects a false one, and a rejected update leaves the item unchanged."""
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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cmp'}, 'val': {'N': '10'}})

    # (operator, true-threshold, new value on success, false-threshold once at that value)
    cases = [
        ('<', '20', '15', '10'),
        ('<=', '15', '16', '15'),
        ('>', '10', '20', '20'),
        ('>=', '20', '25', '30'),
        ('=', '25', '30', '25'),
        ('<>', '999', '35', '35'),
    ]
    for op, true_threshold, new_val, false_threshold in cases:
        _update(ddb, table, 'cmp', new_val, op, true_threshold)
        got = _read(ddb, table, 'cmp')
        assert got['val'] == {'N': new_val}, f"val {op} {true_threshold} should admit the update to {new_val}, got {got['val']}"

        code, message = _rejected_update(ddb, table, 'cmp', '99999', op, false_threshold)
        assert code == ERR_CONDITIONAL_CHECK_FAILED, f"val {op} {false_threshold} should reject with {ERR_CONDITIONAL_CHECK_FAILED}, got {code}"
        assert message == ERR_CONDITIONAL_CHECK_FAILED_MESSAGE, f"val {op} {false_threshold}: expected {ERR_CONDITIONAL_CHECK_FAILED_MESSAGE!r}, got {message!r}"

        got_after = _read(ddb, table, 'cmp')
        assert got_after['val'] == {'N': new_val}, f"rejected update via {op} must leave val at {new_val}, got {got_after['val']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
