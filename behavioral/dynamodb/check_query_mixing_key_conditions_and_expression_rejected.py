"""query-mixing-key-conditions-and-expression-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-mixing-key-conditions-and-expression-rejected"
GROUP = 'legacy'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The legacy KeyConditions parameter and KeyConditionExpression cannot both be sent. AWS names
    which parameters collided, so a target answering a generic error loses that."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error_code(
        lambda: ddb.query(TableName=table, KeyConditionExpression='pk = :v',
                          ExpressionAttributeValues={':v': {'S': 'a'}},
                          KeyConditions={'pk': {'ComparisonOperator': 'EQ',
                                                'AttributeValueList': [{'S': 'a'}]}}),
        'a Query sending both KeyConditions and KeyConditionExpression',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = (
        'Can not use both expression and non-expression parameters in the same request: '
        'Non-expression parameters: {KeyConditions} Expression parameters: {KeyConditionExpression}'
    )
    assert err.get('Message') == expected, f"the message must name the colliding parameters, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
