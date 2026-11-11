"""legacy-queryfilter-scanfilter-keyconditions-argument-rules."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-queryfilter-scanfilter-keyconditions-argument-rules"
GROUP = 'query'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

# (ComparisonOperator, AttributeValueList length given, required length) for each operator
# this check exercises: EQ takes exactly 1, BETWEEN exactly 2, NULL exactly 0.
ARITY_CASES = [
    ('EQ', [{'S': 'Item-0'}, {'S': 'Item-1'}]),
    ('BETWEEN', [{'S': 'Item-0'}]),
    ('NULL', [{'S': 'Item-0'}]),
]


def _error(fn):
    """The Error.Code and Error.Message `fn` raises. Raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A legacy QueryFilter/ScanFilter/KeyConditions entry with the wrong AttributeValueList
    length for its operator, or a ConditionalOperator with no filter, is ValidationException
    with AWS's exact message; a QueryFilter and its FilterExpression twin agree.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.QueryFilter.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
                      AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
                      BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})
    for i in range(3):
        ddb.put_item(TableName=t, Item={'pk': {'S': 'p1'}, 'sk': {'S': f's{i}'}, 'name': {'S': f'Item-{i}'}})

    for op, bad_values in ARITY_CASES:
        want = f'One or more parameter values were invalid: Invalid number of argument(s) for the {op} ComparisonOperator'

        code, message = _error(lambda: ddb.query(
            TableName=t, KeyConditions={'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'}},
            QueryFilter={'name': {'AttributeValueList': bad_values, 'ComparisonOperator': op}}))
        assert code == ERR_VALIDATION, f'QueryFilter/{op}: expected {ERR_VALIDATION}, got {code}'
        assert message == want, f'QueryFilter/{op}: expected AWS exact message, got {message!r}'

        code, message = _error(lambda: ddb.scan(
            TableName=t, ScanFilter={'name': {'AttributeValueList': bad_values, 'ComparisonOperator': op}}))
        assert code == ERR_VALIDATION, f'ScanFilter/{op}: expected {ERR_VALIDATION}, got {code}'
        assert message == want, f'ScanFilter/{op}: expected AWS exact message, got {message!r}'

        code, message = _error(lambda: ddb.query(
            TableName=t, KeyConditions={
                'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'},
                'sk': {'AttributeValueList': bad_values, 'ComparisonOperator': op}}))
        assert code == ERR_VALIDATION, f'KeyConditions/{op}: expected {ERR_VALIDATION}, got {code}'
        assert message == want, f'KeyConditions/{op}: expected AWS exact message, got {message!r}'

    code, message = _error(lambda: ddb.query(
        TableName=t, KeyConditions={'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'}},
        ConditionalOperator='OR'))
    assert code == ERR_VALIDATION, f'Query ConditionalOperator w/o filter: expected {ERR_VALIDATION}, got {code}'
    assert message == 'ConditionalOperator cannot be used without Filter or Expected', (
        f'Query ConditionalOperator w/o filter: expected AWS exact message, got {message!r}'
    )

    code, message = _error(lambda: ddb.scan(TableName=t, ConditionalOperator='OR'))
    assert code == ERR_VALIDATION, f'Scan ConditionalOperator w/o filter: expected {ERR_VALIDATION}, got {code}'
    assert message == 'ConditionalOperator cannot be used without Filter or Expected', (
        f'Scan ConditionalOperator w/o filter: expected AWS exact message, got {message!r}'
    )

    legacy = ddb.query(TableName=t, KeyConditions={'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'}},
                        QueryFilter={'name': {'AttributeValueList': [{'S': 'Item-1'}], 'ComparisonOperator': 'EQ'}},
                        ConsistentRead=True)
    expr = ddb.query(TableName=t, KeyConditionExpression='pk = :p', FilterExpression='#n = :n',
                      ExpressionAttributeNames={'#n': 'name'},
                      ExpressionAttributeValues={':p': {'S': 'p1'}, ':n': {'S': 'Item-1'}},
                      ConsistentRead=True)
    assert legacy['Count'] == 1 == expr['Count'], f"legacy and expression forms disagree on count: {legacy['Count']} vs {expr['Count']}"
    assert legacy['Items'] == expr['Items'], f"legacy QueryFilter and its FilterExpression twin returned different items: {legacy['Items']!r} vs {expr['Items']!r}"
    assert legacy['ScannedCount'] == expr['ScannedCount'] == 3, (
        f"both forms must scan all 3 items under pk=p1 before filtering, got {legacy['ScannedCount']} and {expr['ScannedCount']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
