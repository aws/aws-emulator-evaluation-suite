"""sets-reject-empty-and-duplicate-members."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sets-reject-empty-and-duplicate-members"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _code(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SS, NS and BS are sets, not lists: an empty set and a set with a duplicate member are rejected
    with ValidationException for all three types (also when nested in a map), and nothing is stored.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    legal = {
        'SS': ['a', 'b'],
        'NS': ['1', '2'],
        'BS': [b'\x01', b'\x02'],
    }
    empty = {'SS': [], 'NS': [], 'BS': []}
    dupes = {'SS': ['a', 'a'], 'NS': ['1', '1'], 'BS': [b'\x01', b'\x01']}
    # AWS words each refusal differently per set type, down to spacing and punctuation.
    invalid = '1 validation error detected: One or more parameter values were invalid: '
    empty_message = {
        'SS': invalid + 'An string set  may not be empty',
        'NS': invalid + 'An number set  may not be empty',
        'BS': invalid + 'Binary sets should not be empty',
    }
    dupe_message = {
        'SS': invalid + 'Input collection ["a", "a"] contains duplicates.',
        'NS': invalid + 'Input collection contains duplicates.',
        'BS': invalid + 'Input collection ["AQ==","AQ=="]of type BS contains duplicates.',
    }

    for kind, members in legal.items():
        key = f'ok-{kind}'
        ddb.put_item(TableName=t, Item={'pk': {'S': key}, 's': {kind: members}})
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True).get('Item') or {}
        stored = got.get('s', {}).get(kind)
        assert stored is not None, f'positive control failed: a legal {kind} must round-trip, got {got.get("s")!r}'
        assert len(stored) == 2, f'a 2-member {kind} must keep both members, got {stored!r}'

    for kind in legal:
        key = f'empty-{kind}'
        code, message = _code(lambda k=kind, key=key: ddb.put_item(
            TableName=t, Item={'pk': {'S': key}, 's': {k: empty[k]}}
        ))
        assert code == ERR_VALIDATION, f'an empty {kind} must be {ERR_VALIDATION}, got {code!r}'
        assert message == empty_message[kind], (
            f'an empty {kind}: expected the message {empty_message[kind]!r}, got {message!r}'
        )
        assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True), (
            f'a rejected empty {kind} must not be stored'
        )

    for kind in legal:
        key = f'dupe-{kind}'
        code, message = _code(lambda k=kind, key=key: ddb.put_item(
            TableName=t, Item={'pk': {'S': key}, 's': {k: dupes[k]}}
        ))
        assert code == ERR_VALIDATION, (
            f'a {kind} containing a duplicate must be {ERR_VALIDATION} rather than being '
            f'silently deduplicated or stored as-is, got {code!r}'
        )
        assert message == dupe_message[kind], (
            f'a {kind} containing a duplicate: expected the message {dupe_message[kind]!r}, '
            f'got {message!r}'
        )
        assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True), (
            f'a rejected duplicate-bearing {kind} must not be stored'
        )

    # A set nested inside a map is held to the same rule.
    code, message = _code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'nested-dupe'}, 'm': {'M': {'s': {'SS': ['z', 'z']}}}}
    ))
    assert code == ERR_VALIDATION, f'a duplicate-bearing SS nested in a map must be {ERR_VALIDATION}, got {code!r}'
    assert message == invalid + 'Input collection ["z", "z"] contains duplicates.', (
        f'a duplicate-bearing SS nested in a map: got the message {message!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
