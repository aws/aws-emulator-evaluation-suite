"""update-item-set-list-append-add-exceeding-400kb-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-list-append-add-exceeding-400kb-rejected"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_OVER_LIMIT = 'Item size to update has exceeded the maximum allowed size'
KB = 1024


def _code_and_message(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises.

    An unexpected SUCCESS raises rather than returning a falsy pair: a responder that
    ACCEPTS a growth real AWS refuses is the strongest signal this check can produce.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS rejects this UpdateItem, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UpdateItem that would grow the stored item past 400 KB is rejected with
    ValidationException whichever clause does the growing (SET, list_append, ADD to a
    set), and the stored item is left exactly as it was before the attempt.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-growth-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    oversized = 'x' * (401 * KB)

    # Positive control: an ordinary UpdateItem SET on this table succeeds and reads back,
    # so a target that rejects every UpdateItem (not just oversized ones) cannot pass here.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'control'}})
    ddb.update_item(
        TableName=table, Key={'pk': {'S': 'control'}},
        UpdateExpression='SET note = :v', ExpressionAttributeValues={':v': {'S': 'ok'}},
    )
    control = ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}}, ConsistentRead=True).get('Item', {})
    assert control.get('note', {}).get('S') == 'ok', (
        f'positive control UpdateItem/GetItem round-trip failed, got {control!r}'
    )

    # SET of a large value.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'via-set'}})
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'via-set'}},
        UpdateExpression='SET bigattr = :v', ExpressionAttributeValues={':v': {'S': oversized}},
    ))
    assert code == ERR_VALIDATION, f'SET of a 401KB value must be {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_OVER_LIMIT, f"expected AWS's exact message, got {message!r}"
    after_set = ddb.get_item(TableName=table, Key={'pk': {'S': 'via-set'}}, ConsistentRead=True).get('Item', {})
    assert 'bigattr' not in after_set, f'a rejected SET must leave no trace, item is {after_set!r}'

    # list_append onto an existing list.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'via-list-append'}, 'biglist': {'L': []}})
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'via-list-append'}},
        UpdateExpression='SET biglist = list_append(biglist, :v)',
        ExpressionAttributeValues={':v': {'L': [{'S': oversized}]}},
    ))
    assert code == ERR_VALIDATION, f'list_append growing past 400KB must be {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_OVER_LIMIT, f"expected AWS's exact message, got {message!r}"
    after_list = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'via-list-append'}}, ConsistentRead=True,
    ).get('Item', {})
    assert after_list.get('biglist', {}).get('L') == [], (
        f'a rejected list_append must leave the list exactly as it was, got {after_list!r}'
    )

    # ADD onto an existing string set.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'via-add'}, 'bigset': {'SS': ['seed']}})
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'via-add'}},
        UpdateExpression='ADD bigset :v', ExpressionAttributeValues={':v': {'SS': [oversized]}},
    ))
    assert code == ERR_VALIDATION, f'ADD growing a set past 400KB must be {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_OVER_LIMIT, f"expected AWS's exact message, got {message!r}"
    after_add = ddb.get_item(TableName=table, Key={'pk': {'S': 'via-add'}}, ConsistentRead=True).get('Item', {})
    assert after_add.get('bigset', {}).get('SS') == ['seed'], (
        f'a rejected ADD must leave the set exactly as it was, got {after_add!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
