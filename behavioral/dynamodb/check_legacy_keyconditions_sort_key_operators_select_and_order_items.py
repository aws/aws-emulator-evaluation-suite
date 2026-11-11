"""legacy-keyconditions-sort-key-operators-select-and-order-items."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "legacy-keyconditions-sort-key-operators-select-and-order-items"
GROUP = 'query'
SERVICES = ['dynamodb']

# Ascending byte order of the sort-key values this check seeds: alpha < beta < delta < epsilon < gamma.
SORT_KEYS = ['alpha', 'beta', 'delta', 'epsilon', 'gamma']

# (ComparisonOperator, AttributeValueList, KeyConditionExpression fragment, expected sk's ascending)
OPERATOR_CASES = [
    ('EQ', [{'S': 'delta'}], 'sk = :v0', ['delta']),
    ('LE', [{'S': 'delta'}], 'sk <= :v0', ['alpha', 'beta', 'delta']),
    ('LT', [{'S': 'delta'}], 'sk < :v0', ['alpha', 'beta']),
    ('GE', [{'S': 'delta'}], 'sk >= :v0', ['delta', 'epsilon', 'gamma']),
    ('GT', [{'S': 'delta'}], 'sk > :v0', ['epsilon', 'gamma']),
    ('BEGINS_WITH', [{'S': 'de'}], 'begins_with(sk, :v0)', ['delta']),
    ('BETWEEN', [{'S': 'beta'}, {'S': 'epsilon'}], 'sk BETWEEN :v0 AND :v1', ['beta', 'delta', 'epsilon']),
]


def _sks(resp):
    return [item['sk']['S'] for item in resp['Items']]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A legacy KeyConditions sort-key operator (EQ/LE/LT/GE/GT/BEGINS_WITH/BETWEEN) selects and
    orders the same items as its KeyConditionExpression twin; ScanIndexForward=false reverses the
    order, and a hash-only condition returns the whole partition.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.KeyConditions.html
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
    for sk in SORT_KEYS:
        ddb.put_item(TableName=t, Item={'pk': {'S': 'p1'}, 'sk': {'S': sk}})

    pk_cond = {'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'}}

    for op, values, expr_fragment, expected in OPERATOR_CASES:
        legacy = ddb.query(
            TableName=t,
            KeyConditions={**pk_cond, 'sk': {'AttributeValueList': values, 'ComparisonOperator': op}},
            ConsistentRead=True)
        expr_values = {':p': {'S': 'p1'}}
        for i, v in enumerate(values):
            expr_values[f':v{i}'] = v
        expr = ddb.query(
            TableName=t, KeyConditionExpression=f'pk = :p AND {expr_fragment}',
            ExpressionAttributeValues=expr_values, ConsistentRead=True)

        assert _sks(legacy) == expected, f'{op}: expected {expected!r}, got {_sks(legacy)!r}'
        assert legacy['Count'] == len(expected), f'{op}: expected Count={len(expected)}, got {legacy["Count"]!r}'
        assert _sks(expr) == expected, f'{op} expression twin: expected {expected!r}, got {_sks(expr)!r}'
        assert expr['Count'] == legacy['Count'], (
            f'{op}: legacy Count {legacy["Count"]!r} != expression twin Count {expr["Count"]!r}'
        )

    whole = ddb.query(TableName=t, KeyConditions=pk_cond, ConsistentRead=True)
    assert _sks(whole) == SORT_KEYS, f'hash-only: expected the whole partition {SORT_KEYS!r}, got {_sks(whole)!r}'
    assert whole['Count'] == 5, f'hash-only: expected Count=5, got {whole["Count"]!r}'

    reversed_whole = ddb.query(TableName=t, KeyConditions=pk_cond, ScanIndexForward=False, ConsistentRead=True)
    want_reversed = list(reversed(SORT_KEYS))
    assert _sks(reversed_whole) == want_reversed, (
        f'ScanIndexForward=False: expected {want_reversed!r}, got {_sks(reversed_whole)!r}'
    )

    reversed_gt = ddb.query(
        TableName=t,
        KeyConditions={**pk_cond, 'sk': {'AttributeValueList': [{'S': 'delta'}], 'ComparisonOperator': 'GT'}},
        ScanIndexForward=False, ConsistentRead=True)
    assert _sks(reversed_gt) == ['gamma', 'epsilon'], (
        f"GT delta reversed: expected ['gamma', 'epsilon'], got {_sks(reversed_gt)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
