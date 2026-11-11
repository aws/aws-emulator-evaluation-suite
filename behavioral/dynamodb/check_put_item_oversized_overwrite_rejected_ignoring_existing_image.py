"""put-item-oversized-overwrite-rejected-ignoring-existing-image."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-oversized-overwrite-rejected-ignoring-existing-image"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = ('ValidationException', 'Item size has exceeded the maximum allowed size')
KB = 1024


def _expect_error(fn, code: str, message: str) -> None:
    """Call fn() and grade the exact ClientError code and message it raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        assert err.get('Code') == code, f'expected {code!r}, got {err.get("Code")!r}: {err.get("Message")!r}'
        assert err.get('Message') == message, f'expected message {message!r}, got {err.get("Message")!r}'
        return
    raise AssertionError(f'expected {code!r}, but the call succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem over the 400 KB item-size limit is rejected even when it would overwrite a
    far smaller existing item, and the existing item is left unchanged.
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
    key = {'pk': {'S': 'k'}}

    # Positive control: a normal write to this table succeeds and reads back whole.
    small = 'e' * 900
    ddb.put_item(TableName=t, Item={'pk': {'S': 'k'}, 'blob': {'S': small}})
    existing = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item') or {}
    assert existing.get('blob', {}).get('S') == small, 'the initial small write must read back whole'

    # Break exactly one thing: overwrite that same key with an over-400KB item.
    oversized = 'o' * (410 * KB)
    _expect_error(
        lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'k'}, 'blob': {'S': oversized}}),
        *ERR_VALIDATION,
    )

    # The effect is absent: the pre-existing small item is unchanged, not partially overwritten.
    unchanged = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item') or {}
    assert unchanged.get('blob', {}).get('S') == small, (
        f'a rejected oversized overwrite must leave the existing item unchanged, got '
        f'{unchanged.get("blob", {}).get("S", "")!r} (truncated to length for readability: '
        f'{len(unchanged.get("blob", {}).get("S", ""))})'
    )

    # Positive control after the rejection: the table still accepts ordinary writes.
    other_key = {'pk': {'S': 'k2'}}
    ddb.put_item(TableName=t, Item={'pk': {'S': 'k2'}, 'blob': {'S': small}})
    other = ddb.get_item(TableName=t, Key=other_key, ConsistentRead=True).get('Item') or {}
    assert other.get('blob', {}).get('S') == small, 'an ordinary write after the rejection must still succeed'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
