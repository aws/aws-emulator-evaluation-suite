"""empty-and-duplicate-set-members-rejected-for-ss-ns-and-bs."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-and-duplicate-set-members-rejected-for-ss-ns-and-bs"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Empty SS/NS/BS sets and duplicate members (incl. NS '1' vs '1.0', and duplicates inside a
    ConditionExpression value or a GetItem key) are refused ValidationException with AWS's exact
    messages and store/read nothing; legal sets and an SS with an empty-string member round-trip."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-sets-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- positive controls: one legal two-member set per type, on the same table ---
    controls = {
        'ok-ss': {'SS': ['a', 'b']},
        'ok-ns': {'NS': ['1', '2']},
        'ok-bs': {'BS': [b'a', b'b']},
    }
    for key, value in controls.items():
        ddb.put_item(TableName=t, Item={'pk': {'S': key}, 's': value})
    for key, value in controls.items():
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True).get('Item', {})
        kind = next(iter(value))
        members = got.get('s', {}).get(kind)
        assert members is not None, (
            f'control: a legal two-member {kind} must round-trip as a {kind}, got {got.get("s")!r}'
        )
        assert len(members) == 2, (
            f'control: a legal two-member {kind} must keep both members, got {members!r}'
        )

    # --- the rejections: empty and duplicate, for each of the three set types ---
    invalid = '1 validation error detected: One or more parameter values were invalid: '
    rejections = {
        'ss-empty': ('an empty string set', {'pk': {'S': 'ss-empty'}, 's': {'SS': []}},
                     invalid + 'An string set  may not be empty'),
        'ss-dup': ('a string set with a repeated member', {'pk': {'S': 'ss-dup'}, 's': {'SS': ['a', 'a']}},
                   invalid + 'Input collection ["a", "a"] contains duplicates.'),
        'ns-empty': ('an empty number set', {'pk': {'S': 'ns-empty'}, 's': {'NS': []}},
                     invalid + 'An number set  may not be empty'),
        'ns-dup': ('a number set with a repeated member', {'pk': {'S': 'ns-dup'}, 's': {'NS': ['1', '1']}},
                   invalid + 'Input collection contains duplicates.'),
        'ns-dup-canonical': ("a number set whose members ('1' and '1.0') are equal once canonicalized",
                             {'pk': {'S': 'ns-dup-canonical'}, 's': {'NS': ['1', '1.0']}},
                             invalid + 'Input collection contains duplicates.'),
        'bs-empty': ('an empty binary set', {'pk': {'S': 'bs-empty'}, 's': {'BS': []}},
                     invalid + 'Binary sets should not be empty'),
        'bs-dup': ('a binary set with a repeated member', {'pk': {'S': 'bs-dup'}, 's': {'BS': [b'a', b'a']}},
                   invalid + 'Input collection ["YQ==","YQ=="]of type BS contains duplicates.'),
        'ss-dup-in-m': ('a string set with a repeated member nested inside an M',
                        {'pk': {'S': 'ss-dup-in-m'}, 'm': {'M': {'s': {'SS': ['a', 'a']}}}},
                        invalid + 'Input collection ["a", "a"] contains duplicates.'),
    }
    for _key, (why, item, expected_message) in rejections.items():
        code, message = _error_code(lambda item=item: ddb.put_item(TableName=t, Item=item),
                                    f'PutItem with {why}')
        assert code == ERR_VALIDATION, (
            f'{why} is not a legal set and must be refused {ERR_VALIDATION}, got {code!r}'
        )
        assert message == expected_message, (
            f'{why}: expected the message {expected_message!r}, got {message!r}'
        )

    # A silently de-duplicated write would return the same 200, so read back to prove none stored.
    for key, (why, _item, _message) in rejections.items():
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True)
        assert 'Item' not in got, (
            f'the write refused for {why} must leave nothing behind -- in particular it must not be '
            f'silently de-duplicated and stored -- got {got.get("Item")!r}'
        )

    # --- the same duplicate-member rule applies off a ConditionExpression value ... ---
    expected_cond_message = invalid + 'Input collection ["z", "z"] contains duplicates.'
    code, message = _error_code(
        lambda: ddb.put_item(
            TableName=t,
            Item={'pk': {'S': 'ok-ss'}, 's': {'SS': ['c', 'd']}},
            ConditionExpression='contains(:dup, :needle)',
            ExpressionAttributeValues={':dup': {'SS': ['z', 'z']}, ':needle': {'S': 'z'}},
        ),
        'PutItem whose ConditionExpression value is a string set with a repeated member',
    )
    assert code == ERR_VALIDATION, (
        f'a duplicate-member set used as a ConditionExpression value must be refused '
        f'{ERR_VALIDATION}, got {code!r}'
    )
    assert message == expected_cond_message, (
        f'expected the message {expected_cond_message!r}, got {message!r}'
    )
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'ok-ss'}}, ConsistentRead=True).get('Item', {})
    assert sorted(got.get('s', {}).get('SS', [])) == ['a', 'b'], (
        f'the conditional write refused for an invalid ConditionExpression value must leave the '
        f'existing item untouched, got {got.get("s")!r}'
    )

    # --- ... and off a GetItem key, where AWS validates the key's set shape before reading ---
    expected_key_message = 'One or more parameter values were invalid: Input collection ["a", "a"] contains duplicates.'
    code, message = _error_code(
        lambda: ddb.get_item(TableName=t, Key={'pk': {'SS': ['a', 'a']}}),
        'GetItem whose key value is a string set with a repeated member',
    )
    assert code == ERR_VALIDATION, (
        f'a duplicate-member set used as a GetItem key value must be refused {ERR_VALIDATION}, '
        f'got {code!r}'
    )
    assert message == expected_key_message, (
        f'expected the message {expected_key_message!r}, got {message!r}'
    )

    # --- an empty STRING is a legal member: this is not the "no empty values" rule ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'ss-empty-member'}, 's': {'SS': ['', 'a']}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'ss-empty-member'}},
                       ConsistentRead=True).get('Item', {})
    members = got.get('s', {}).get('SS')
    assert members is not None, (
        f'an empty string is a legal SS member, so this write must be accepted and readable, got '
        f'{got.get("s")!r}'
    )
    assert sorted(members) == ['', 'a'], (
        f"an SS containing an empty string must round-trip with both members, got {members!r}"
    )

    scanned = ddb.scan(TableName=t, ConsistentRead=True, Select='COUNT')
    assert scanned['Count'] == 4, (
        f'only the three legal set controls and the empty-string-member item may exist after eight '
        f'refused writes, got {scanned["Count"]!r} items'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
