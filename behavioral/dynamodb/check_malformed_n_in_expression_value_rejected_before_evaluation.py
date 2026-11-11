"""malformed-n-in-expression-value-rejected-before-evaluation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-n-in-expression-value-rejected-before-evaluation"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_CONDITIONAL = 'ConditionalCheckFailedException'

# Each form is malformed in a different way: unparsable mantissa, an empty string, and a
# mantissa that parses but overflows the documented magnitude range.
_MALFORMED = ['abc', '', '1e99999']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error']['Message']
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A malformed N in a ConditionExpression, legacy Expected or UpdateExpression value is
    ValidationException, not ConditionalCheckFailedException, even when the condition would
    also fail on a well-formed value -- validation precedes evaluation, item untouched.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes.Number
    """
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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    key = {'pk': {'S': 'item'}}
    ddb.put_item(TableName=table, Item={'pk': {'S': 'item'}, 'v': {'N': '5'}, 'note': {'S': 'orig'}})

    def unchanged():
        item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
        assert item == {'pk': {'S': 'item'}, 'v': {'N': '5'}, 'note': {'S': 'orig'}}, (
            f'item must be untouched by every rejected call, got {item!r}'
        )

    # --- positive control: a WELL-FORMED but non-matching condition fails with
    # ConditionalCheckFailedException, proving the two errors are distinguishable and that the
    # malformed-value rejections below are not merely "this condition never matches". ---
    code, message = _error(lambda: ddb.put_item(
        TableName=table,
        Item={'pk': {'S': 'item'}, 'v': {'N': '99'}, 'note': {'S': 'changed'}},
        ConditionExpression='v = :cond',
        ExpressionAttributeValues={':cond': {'N': '7'}},
    ))
    assert code == ERR_CONDITIONAL, f'well-formed non-matching condition must fail with {ERR_CONDITIONAL}, got {code}'
    assert message == 'The conditional request failed', f"expected AWS's exact message, got {message!r}"
    unchanged()

    for mv in _MALFORMED:
        # --- malformed N in a ConditionExpression value, against a condition that would also
        # fail on a well-formed value (v=5 never equals 7) ---
        code, message = _error(lambda mv=mv: ddb.put_item(
            TableName=table,
            Item={'pk': {'S': 'item'}, 'v': {'N': '99'}, 'note': {'S': 'changed'}},
            ConditionExpression='v = :cond',
            ExpressionAttributeValues={':cond': {'N': mv}},
        ))
        assert code == ERR_VALIDATION, (
            f'malformed N {mv!r} in ConditionExpression value must be {ERR_VALIDATION}, got {code}'
        )
        expected = (
            "1 validation error detected: Number overflow. Attempting to store a number with "
            "magnitude larger than supported range"
        ) if mv == '1e99999' else (
            f"1 validation error detected: The parameter cannot be converted to a numeric value: {mv}"
        )
        assert message == expected, f"expected AWS's exact message, got {message!r}"
        unchanged()

        # --- malformed N in a legacy Expected value, against a condition that would also fail
        # on a well-formed value (v=5 never equals 7) ---
        code, message = _error(lambda mv=mv: ddb.put_item(
            TableName=table,
            Item={'pk': {'S': 'item'}, 'v': {'N': '99'}, 'note': {'S': 'changed'}},
            Expected={'v': {'Value': {'N': mv}}},
        ))
        assert code == ERR_VALIDATION, (
            f'malformed N {mv!r} in legacy Expected value must be {ERR_VALIDATION}, got {code}'
        )
        assert message == expected, f"expected AWS's exact message, got {message!r}"
        unchanged()

        # --- malformed N in an UpdateExpression SET value, guarded by a ConditionExpression
        # that would also fail on a well-formed value ---
        code, message = _error(lambda mv=mv: ddb.update_item(
            TableName=table,
            Key=key,
            UpdateExpression='SET note = :val',
            ConditionExpression='v = :cond',
            ExpressionAttributeValues={':val': {'N': mv}, ':cond': {'N': '7'}},
        ))
        assert code == ERR_VALIDATION, (
            f'malformed N {mv!r} in UpdateExpression value must be {ERR_VALIDATION}, got {code}'
        )
        assert message == expected, f"expected AWS's exact message, got {message!r}"
        unchanged()

    # Control still works after every rejection.
    ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression='SET note = :val',
        ExpressionAttributeValues={':val': {'S': 'final'}},
    )
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert item['note'] == {'S': 'final'}, f'control update must still succeed, got {item!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
