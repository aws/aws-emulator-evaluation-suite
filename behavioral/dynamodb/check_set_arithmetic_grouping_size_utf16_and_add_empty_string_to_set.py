"""set-arithmetic-grouping-size-utf16-and-add-empty-string-to-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-arithmetic-grouping-size-utf16-and-add-empty-string-to-set"
GROUP = 'expressions'
SERVICES = ['dynamodb']

_ASTRAL_CHAR = '\U0001F600'


def _wait_table_active(ddb, ctx, name):
    """Wait for the table to become ACTIVE, bounded by the check's own remaining budget."""
    budget = max(10.0, min(120.0, (ctx.time_left() or 120.0) - 10.0))
    delay = 2
    attempts = max(1, int(budget // delay))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={'Delay': delay, 'MaxAttempts': attempts})


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SET n = (n - :d) evaluates the parenthesised subtraction; a Query FilterExpression's
    size() counts a string in UTF-16 code units, so one astral-plane character counts as 2;
    ADD accepts an empty string as a new member of a string set.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-ddb-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    _wait_table_active(ddb, ctx, t)

    # SET n = (n - :d): the parenthesised arithmetic is applied before assignment.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'p'}, 'sk': {'S': 'counter'}, 'n': {'N': '10'}})
    updated = ddb.update_item(
        TableName=t, Key={'pk': {'S': 'p'}, 'sk': {'S': 'counter'}},
        UpdateExpression='SET n = (n - :d)', ExpressionAttributeValues={':d': {'N': '3'}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert updated['n'] == {'N': '7'}, (
        f"SET n = (n - :d) from n=10 with :d=3 produced n={updated.get('n')!r}, expected {{'N': '7'}}"
    )

    # size() on a Query FilterExpression counts UTF-16 code units: one astral-plane character
    # (one Unicode code point, encoded as a surrogate pair) counts as 2, the same as two ASCII
    # characters.
    rows = {
        'one-astral-char': _ASTRAL_CHAR,
        'two-ascii-chars': 'ab',
        'three-ascii-chars': 'abc',
    }
    for sk, text in rows.items():
        ddb.put_item(TableName=t, Item={'pk': {'S': 'p'}, 'sk': {'S': sk}, 'txt': {'S': text}})
    matched = ddb.query(
        TableName=t, KeyConditionExpression='pk = :p',
        FilterExpression='size(txt) = :n',
        ExpressionAttributeValues={':p': {'S': 'p'}, ':n': {'N': '2'}},
        ConsistentRead=True,
    )
    matched_sks = {item['sk']['S'] for item in matched['Items']}
    assert matched_sks == {'one-astral-char', 'two-ascii-chars'}, (
        f"size(txt) = 2 matched {matched_sks!r}, expected {{'one-astral-char', 'two-ascii-chars'}}: "
        f"a single astral-plane character must count as 2 UTF-16 code units, the same as two "
        f"ASCII characters, and 'abc' (3 code units) must not match"
    )

    # ADD accepts an empty string as a new member of an existing string set.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'p'}, 'sk': {'S': 'tags'}, 'tags': {'SS': ['x']}})
    added = ddb.update_item(
        TableName=t, Key={'pk': {'S': 'p'}, 'sk': {'S': 'tags'}},
        UpdateExpression='ADD tags :e', ExpressionAttributeValues={':e': {'SS': ['']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert set(added['tags']['SS']) == {'', 'x'}, (
        f"ADD tags :e with :e={{'SS': ['']}} against an existing SS of ['x'] produced "
        f"{added.get('tags')!r}, expected the set {{'', 'x'}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
