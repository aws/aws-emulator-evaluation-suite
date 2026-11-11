"""legacy-keyconditions-disallowed-sort-key-operator-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-keyconditions-disallowed-sort-key-operator-rejected"
GROUP = 'query'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

# A sort-key ComparisonOperator outside EQ/LE/LT/GE/GT/BEGINS_WITH/BETWEEN, each with an arity
# that is otherwise valid for the operator so only the operator itself is under test.
DISALLOWED_CASES = [
    ('NE', [{'S': 'beta'}]),
    ('CONTAINS', [{'S': 'e'}]),
    ('NULL', []),
]


def _error(fn):
    """The Error.Code and Error.Message `fn` raises. Raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A legacy KeyConditions sort-key entry using a comparison operator other than
    EQ/LE/LT/GE/GT/BEGINS_WITH/BETWEEN is ValidationException with AWS's exact message, while
    the same partition key condition alone is accepted.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'p1'}, 'sk': {'S': 'alpha'}})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'p1'}, 'sk': {'S': 'beta'}})

    pk_cond = {'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'}}

    want = 'One or more parameter values were invalid: Attempted conditional constraint is not an indexable operation'
    for op, values in DISALLOWED_CASES:
        code, message = _error(lambda: ddb.query(
            TableName=t,
            KeyConditions={**pk_cond, 'sk': {'AttributeValueList': values, 'ComparisonOperator': op}}))
        assert code == ERR_VALIDATION, f'{op}: expected {ERR_VALIDATION}, got {code!r}'
        assert message == want, f'{op}: expected AWS exact message, got {message!r}'

    positive = ddb.query(TableName=t, KeyConditions=pk_cond, ConsistentRead=True)
    assert positive['Count'] == 2, f'positive control: expected Count=2, got {positive["Count"]!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
