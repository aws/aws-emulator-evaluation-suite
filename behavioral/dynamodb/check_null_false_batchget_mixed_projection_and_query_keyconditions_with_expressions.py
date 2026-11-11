"""null-false-batchget-mixed-projection-and-query-keyconditions-with-expressions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "null-false-batchget-mixed-projection-and-query-keyconditions-with-expressions"
GROUP = 'legacy'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


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
    """A NULL attribute value of false is rejected; BatchGetItem refuses request-wide when
    one table's Keys use ProjectionExpression and another's use AttributesToGet; Query
    accepts legacy KeyConditions paired with ProjectionExpression or FilterExpression.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.html
    """
    ddb = ctx.client('dynamodb')
    t1 = ctx.unique_name('sim2real-behav-a-')
    t2 = ctx.unique_name('sim2real-behav-b-')
    for t in (t1, t2):
        ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                          AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                          BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
        ctx.on_cleanup(lambda t=t: ddb.delete_table(TableName=t))
    for t in (t1, t2):
        ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})

    # --- 1. PutItem with {"NULL": false} is rejected; {"NULL": true} is the only legal form.
    code, message = _error(lambda: ddb.put_item(TableName=t1, Item={'pk': {'S': 'n1'}, 'flag': {'NULL': False}}))
    assert code == ERR_VALIDATION, f'NULL:false: expected {ERR_VALIDATION}, got {code}'
    assert message == '1 validation error detected: One or more parameter values were invalid: Null attribute value types must have the value of true', (
        f'NULL:false: expected AWS exact message, got {message!r}'
    )
    absent = ddb.get_item(TableName=t1, Key={'pk': {'S': 'n1'}}, ConsistentRead=True).get('Item')
    assert absent is None, f'a rejected NULL:false PutItem must not have created the item: {absent!r}'
    ddb.put_item(TableName=t1, Item={'pk': {'S': 'n1'}, 'flag': {'NULL': True}})
    landed = ddb.get_item(TableName=t1, Key={'pk': {'S': 'n1'}}, ConsistentRead=True).get('Item')
    assert landed == {'pk': {'S': 'n1'}, 'flag': {'NULL': True}}, f'positive control NULL:true did not land: {landed!r}'

    # --- 2. BatchGetItem refuses request-wide when one table's Keys use ProjectionExpression
    #        and another's use AttributesToGet -- even though they name different tables.
    ddb.put_item(TableName=t1, Item={'pk': {'S': 'k1'}, 'a': {'S': 'A'}, 'b': {'S': 'B'}})
    ddb.put_item(TableName=t2, Item={'pk': {'S': 'k1'}, 'c': {'S': 'C'}, 'd': {'S': 'D'}})
    code, message = _error(lambda: ddb.batch_get_item(RequestItems={
        t1: {'Keys': [{'pk': {'S': 'k1'}}], 'ProjectionExpression': 'a'},
        t2: {'Keys': [{'pk': {'S': 'k1'}}], 'AttributesToGet': ['c']},
    }))
    assert code == ERR_VALIDATION, f'mixed BatchGetItem: expected {ERR_VALIDATION}, got {code}'
    assert message == (
        'Can not use both expression and non-expression parameters in the same request: '
        'Non-expression parameters: {AttributesToGet} Expression parameters: {ProjectionExpression}'
    ), f'mixed BatchGetItem: expected AWS exact message naming the colliding parameters, got {message!r}'
    # Positive control: ProjectionExpression on both tables' Keys entries is accepted.
    ok = ddb.batch_get_item(RequestItems={
        t1: {'Keys': [{'pk': {'S': 'k1'}}], 'ProjectionExpression': 'a'},
        t2: {'Keys': [{'pk': {'S': 'k1'}}], 'ProjectionExpression': 'c'},
    })
    assert ok['Responses'][t1] == [{'a': {'S': 'A'}}], f'positive control t1 projection wrong: {ok["Responses"][t1]!r}'
    assert ok['Responses'][t2] == [{'c': {'S': 'C'}}], f'positive control t2 projection wrong: {ok["Responses"][t2]!r}'

    # --- 3. Query accepts legacy KeyConditions paired with ProjectionExpression, honouring both.
    proj = ddb.query(TableName=t1, KeyConditions={'pk': {'AttributeValueList': [{'S': 'k1'}], 'ComparisonOperator': 'EQ'}},
                      ProjectionExpression='a', ConsistentRead=True)
    assert proj['Count'] == 1, f'KeyConditions+ProjectionExpression: expected 1 match, got {proj["Count"]}'
    assert proj['Items'] == [{'a': {'S': 'A'}}], f'KeyConditions+ProjectionExpression did not project to just a: {proj["Items"]!r}'

    # --- 4. Query accepts legacy KeyConditions paired with FilterExpression, and the filter
    #        actually narrows the key-matched set, not merely accepted and ignored.
    t3 = ctx.unique_name('sim2real-behav-c-')
    ddb.create_table(TableName=t3, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
                      AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
                      BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t3))
    ddb.get_waiter('table_exists').wait(TableName=t3, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})
    for i in range(3):
        ddb.put_item(TableName=t3, Item={'pk': {'S': 'p1'}, 'sk': {'S': f's{i}'}, 'tag': {'S': 'keep' if i == 1 else 'drop'}})
    filt = ddb.query(TableName=t3, KeyConditions={'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'}},
                      FilterExpression='tag = :t', ExpressionAttributeValues={':t': {'S': 'keep'}}, ConsistentRead=True)
    assert filt['Count'] == 1, f'KeyConditions+FilterExpression: expected 1 surviving item, got {filt["Count"]}'
    assert filt['Items'][0]['sk'] == {'S': 's1'}, f'KeyConditions+FilterExpression kept the wrong item: {filt["Items"]!r}'
    assert filt['ScannedCount'] == 3, (
        f'KeyConditions+FilterExpression is a post-condition filter: all 3 items under the key must be '
        f'scanned before the filter drops it to 1, got ScannedCount={filt["ScannedCount"]!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
