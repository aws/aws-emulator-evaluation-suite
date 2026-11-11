"""put-item-two-empty-members-in-ss-and-bs-rejected-as-duplicate-collections."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-two-empty-members-in-ss-and-bs-rejected-as-duplicate-collections"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it, got {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A two-member SS or BS whose members are both the empty string/bytes is refused
    ValidationException as a duplicate collection, not as an empty one, and nothing is stored.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-emptydup-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- positive controls: a single empty-string/empty-bytes member is a legal, non-duplicate
    # member of a two-element set, so these round-trip. ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'ok-ss'}, 's': {'SS': ['', 'a']}})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'ok-bs'}, 's': {'BS': [b'', b'a']}})
    for key, kind, want in (('ok-ss', 'SS', ['', 'a']), ('ok-bs', 'BS', [b'', b'a'])):
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True).get('Item', {})
        members = got.get('s', {}).get(kind)
        assert sorted(members or []) == want, (
            f'control: a legal two-member {kind} with one empty member must round-trip as {want!r}, '
            f'got {got.get("s")!r}'
        )

    # --- the rejections: two empty members of the same type are duplicates of each other ---
    invalid = '1 validation error detected: One or more parameter values were invalid: '
    expected_ss_message = invalid + 'Input collection ["", ""] contains duplicates.'
    expected_bs_message = invalid + 'Input collection ["",""]of type BS contains duplicates.'

    code, message = _error_code(
        lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'ss-two-empty'}, 's': {'SS': ['', '']}}),
        'PutItem with an SS of two empty-string members',
    )
    assert code == ERR_VALIDATION, (
        f'an SS of two empty-string members must be refused {ERR_VALIDATION} as a duplicate '
        f'collection, got {code!r}'
    )
    assert message == expected_ss_message, (
        f'expected the message {expected_ss_message!r}, got {message!r}'
    )

    code, message = _error_code(
        lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'bs-two-empty'}, 's': {'BS': [b'', b'']}}),
        'PutItem with a BS of two empty-bytes members',
    )
    assert code == ERR_VALIDATION, (
        f'a BS of two empty-bytes members must be refused {ERR_VALIDATION} as a duplicate '
        f'collection, got {code!r}'
    )
    assert message == expected_bs_message, (
        f'expected the message {expected_bs_message!r}, got {message!r}'
    )

    # A silently de-duplicated write would return the same 200, so read back to prove neither stored.
    for key in ('ss-two-empty', 'bs-two-empty'):
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True)
        assert 'Item' not in got, (
            f'a write refused as a duplicate collection must leave nothing behind, got {got.get("Item")!r}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
