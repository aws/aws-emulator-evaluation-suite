"""select-non-specific-values-reject-projection-expression."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "select-non-specific-values-reject-projection-expression"
GROUP = 'query'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'

# The Select value a request names, and the exact AWS message for pairing it with
# ProjectionExpression (only SPECIFIC_ATTRIBUTES may be).
_REJECTED = {
    'ALL_ATTRIBUTES': (
        '1 validation error detected: Cannot specify the ProjectionExpression when '
        'choosing to get ALL_ATTRIBUTES'
    ),
    'COUNT': (
        '1 validation error detected: Cannot specify the ProjectionExpression when '
        'choosing to get only the Count'
    ),
    'ALL_PROJECTED_ATTRIBUTES': (
        '1 validation error detected: Cannot specify the ProjectionExpression when '
        'choosing to get ALL_PROJECTED_ATTRIBUTES'
    ),
}


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _code(fn):
    """The error code and message *fn* raises; an unexpected success fails loudly instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Query and Scan refuse ALL_ATTRIBUTES, COUNT and ALL_PROJECTED_ATTRIBUTES paired
    with a ProjectionExpression: only SPECIFIC_ATTRIBUTES may carry one.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Query.html#DDB-Query-request-Select
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-select-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    delay = 2
    budget_s = _budget_s(ctx, 120.0)
    ddb.get_waiter('table_exists').wait(
        TableName=table, WaiterConfig={'Delay': delay, 'MaxAttempts': max(1, int(budget_s / delay))}
    )

    item = {'pk': {'S': 'P'}, 'sk': {'S': 'S'}, 'body': {'S': 'payload'}}
    ddb.put_item(TableName=table, Item=item)

    query_base = {
        'TableName': table,
        'KeyConditionExpression': 'pk = :p',
        'ExpressionAttributeValues': {':p': {'S': 'P'}},
        'ConsistentRead': True,
    }
    scan_base = {'TableName': table, 'ConsistentRead': True}

    for select, message in _REJECTED.items():
        code, msg = _code(lambda s=select: ddb.query(**query_base, Select=s, ProjectionExpression='body'))
        assert code == ERR_VALIDATION, (
            f'Query Select={select} with a ProjectionExpression must be refused with '
            f'{ERR_VALIDATION}; got {code}'
        )
        assert msg == message, f'Query Select={select}: expected AWS message {message!r}, got {msg!r}'

        code, msg = _code(lambda s=select: ddb.scan(**scan_base, Select=s, ProjectionExpression='body'))
        assert code == ERR_VALIDATION, (
            f'Scan Select={select} with a ProjectionExpression must be refused with '
            f'{ERR_VALIDATION}; got {code}'
        )
        assert msg == message, f'Scan Select={select}: expected AWS message {message!r}, got {msg!r}'

    # Positive control: the same request, legally paired (SPECIFIC_ATTRIBUTES + ProjectionExpression),
    # still succeeds through both operations.
    query_resp = ddb.query(**query_base, Select='SPECIFIC_ATTRIBUTES', ProjectionExpression='body')
    assert query_resp['Items'] == [{'body': {'S': 'payload'}}], (
        f'legal Query Select=SPECIFIC_ATTRIBUTES + ProjectionExpression should still work, '
        f'got {query_resp["Items"]!r}'
    )
    scan_resp = ddb.scan(**scan_base, Select='SPECIFIC_ATTRIBUTES', ProjectionExpression='body')
    assert scan_resp['Items'] == [{'body': {'S': 'payload'}}], (
        f'legal Scan Select=SPECIFIC_ATTRIBUTES + ProjectionExpression should still work, '
        f'got {scan_resp["Items"]!r}'
    )

    # None of the six rejected calls wrote, deleted or altered anything: the table still holds
    # exactly the one item this check put, unchanged.
    final = ddb.scan(TableName=table, ConsistentRead=True)
    assert final['Items'] == [item], (
        f'the six rejected Select+ProjectionExpression combinations must have no side effect; '
        f'table holds {final["Items"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
