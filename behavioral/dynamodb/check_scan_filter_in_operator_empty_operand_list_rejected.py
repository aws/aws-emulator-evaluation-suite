"""scan-filter-in-operator-empty-operand-list-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'scan-filter-in-operator-empty-operand-list-rejected'
GROUP = 'expressions'
SERVICES = ['dynamodb']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error']['Message']
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterExpression 'IN ()' with no operands is rejected; the same Binary attribute still
    matches a non-empty IN list on a later scan.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), 'ResourceNotFoundException'))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'u1'}, 'blob': {'B': b'\x00\x01\x02'}})

    code, message = _error(lambda: ddb.scan(
        TableName=t,
        FilterExpression='#b IN ()',
        ExpressionAttributeNames={'#b': 'blob'},
    ))
    assert (code, message) == (
        'ValidationException',
        'Invalid FilterExpression: Syntax error; token: ")", near: "()"',
    ), f"empty IN operand list gave ({code!r}, {message!r})"

    resp = ddb.scan(
        TableName=t,
        FilterExpression='#b IN (:v1)',
        ExpressionAttributeNames={'#b': 'blob'},
        ExpressionAttributeValues={':v1': {'B': b'\x00\x01\x02'}},
        ConsistentRead=True,
    )
    pks = {item['pk']['S'] for item in resp['Items']}
    assert pks == {'u1'}, f"a non-empty IN after the refusal expected {{'u1'}}, got {pks}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
