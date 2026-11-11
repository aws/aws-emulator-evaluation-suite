"""condition-size-counts-string-length-not-bytes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "condition-size-counts-string-length-not-bytes"
GROUP = 'conditions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """size() on a String counts UTF-16 code units: a 3-character multi-byte BMP string has
    size 3 (not 7 UTF-8 bytes), and a single astral-plane character -- one code point, one
    surrogate pair -- has size 2, exactly so in a ConditionExpression and a Query FilterExpression."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table,
                     KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                                {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                                           {'AttributeName': 'sk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    # 'e' with an accent, a Greek letter and a CJK character: 3 characters, 7 UTF-8 bytes.
    value = '\u00e9\u03b1\u4e2d'
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': 'bmp'}, 's': {'S': value}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': 'bmp'}, 's': {'S': value}, 'ok': {'N': '1'}},
                 ConditionExpression='size(s) = :n',
                 ExpressionAttributeValues={':n': {'N': '3'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}, 'sk': {'S': 'bmp'}},
                       ConsistentRead=True)['Item']
    assert got.get('ok') == {'N': '1'}, (
        f'size() must count the 3 characters rather than the 7 UTF-8 bytes, got {got}'
    )

    # An astral-plane character is one code point and one grapheme, but UTF-16 represents it
    # as a surrogate pair, so size() reports 2 for one such character -- not 1, as a code-point
    # counter would, and not 4, as a UTF-8-byte counter would.
    astral = '\U0001f600'
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': 'astral1'}, 's': {'S': astral}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': 'astral1'}, 's': {'S': astral}, 'ok': {'N': '1'}},
                 ConditionExpression='size(s) = :n',
                 ExpressionAttributeValues={':n': {'N': '2'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}, 'sk': {'S': 'astral1'}},
                       ConsistentRead=True)['Item']
    assert got.get('ok') == {'N': '1'}, (
        f'size() must count one astral-plane character as 2 (its UTF-16 surrogate pair), got {got}'
    )

    # Two astral-plane characters concatenated: size() reports 4, as AWS actually measures it.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': 'astral2'}, 's': {'S': astral + astral}})

    # A Query FilterExpression applies size() over the matched partition the same way: each
    # sort key's item is returned only under the size its own string actually measures as.
    by_size_2 = ddb.query(TableName=table, KeyConditionExpression='pk = :p',
                         FilterExpression='size(s) = :n',
                         ExpressionAttributeValues={':p': {'S': 'a'}, ':n': {'N': '2'}})['Items']
    assert {i['sk']['S'] for i in by_size_2} == {'astral1'}, (
        f'a FilterExpression of size(s) = 2 must match only the single astral character, got {by_size_2!r}'
    )
    by_size_4 = ddb.query(TableName=table, KeyConditionExpression='pk = :p',
                         FilterExpression='size(s) = :n',
                         ExpressionAttributeValues={':p': {'S': 'a'}, ':n': {'N': '4'}})['Items']
    assert {i['sk']['S'] for i in by_size_4} == {'astral2'}, (
        f'a FilterExpression of size(s) = 4 must match only the doubled astral character, got {by_size_4!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
