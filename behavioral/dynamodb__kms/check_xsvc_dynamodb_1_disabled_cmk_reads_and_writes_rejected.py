"""xsvc-dynamodb-1-disabled-cmk-reads-and-writes-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-1-disabled-cmk-reads-and-writes-rejected"
GROUP = 'sse_kms'
SERVICES = ['dynamodb', 'kms']

_KMS_TAGS = [{"TagKey": "sim2real", "TagValue": "dynamodb-sse-cmk"}]
_DDB_TAGS = [{"Key": "sim2real", "Value": "dynamodb-sse-cmk"}]

# Once DynamoDB's cached table key lapses, GetItem and PutItem on a table whose CMK is DISABLED fail
# ValidationException "KMS key disabled error: com.amazonaws.services.kms.model.DisabledException:
# <key arn> is disabled. ...": DynamoDB wraps the KMS cause.
ERR = 'ValidationException'
KMS_CAUSE = 'DisabledException'
# DynamoDB caches the table key, so reads and writes keep succeeding after DisableKey for a
# nondeterministic window (seconds to ~5 minutes); the poll must outlast that cache.
_REJECT_CEILING_S = 480
_RESTORE_CEILING_S = 180


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; raise if fn succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        e = exc.response.get('Error', {})
        return e.get('Code'), e.get('Message', '')
    raise AssertionError(f'expected a ClientError, but the call succeeded: {resp!r}')


def _wait_active(ddb, table, deadline_s=240):
    end = time.time() + deadline_s
    while time.time() < end:
        t = ddb.describe_table(TableName=table)['Table']
        if t['TableStatus'] == 'ACTIVE':
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never reached ACTIVE within {deadline_s}s')


def _cmk(ctx, kms, label):
    key = kms.create_key(Description=f'sim2real-xsvc-ddb-sse-{label}-{uuid.uuid4().hex[:8]}',
                         KeyUsage='ENCRYPT_DECRYPT', Tags=_KMS_TAGS)['KeyMetadata']
    # KMS has no immediate delete: 7 days is the minimum PendingWindowInDays.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key['KeyId'], PendingWindowInDays=7))
    return key['KeyId'], key['Arn']


def _cmk_table(ctx, ddb, key_arn):
    table = ctx.unique_name('sim2real-xsvc-ddbkms-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        SSESpecification={'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': key_arn},
        Tags=_DDB_TAGS,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    return table


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Disabling a table's CMK makes GetItem and PutItem fail ValidationException (naming the KMS
    DisabledException) while a table on another enabled CMK keeps working; re-enabling the key
    restores reads and writes and the item written before the disable is intact.
    """
    kms = ctx.client('kms')
    ddb = ctx.client('dynamodb')
    token = uuid.uuid4().hex[:8]
    item = {'pk': {'S': f'kept-{token}'}, 'v': {'S': f'written-before-disable|日本語-{token}'}}

    target_id, target_arn = _cmk(ctx, kms, 'disable-target')
    _, control_arn = _cmk(ctx, kms, "disable-control")
    target = _cmk_table(ctx, ddb, target_arn)
    control = _cmk_table(ctx, ddb, control_arn)
    for table, arn in ((target, target_arn), (control, control_arn)):
        sse = _wait_active(ddb, table).get('SSEDescription') or {}
        assert sse.get('KMSMasterKeyArn') == arn, (
            f'{table} is not encrypted with the CMK this check created, so disabling that key '
            f'proves nothing: {sse!r}, expected {arn!r}'
        )

    # --- control FIRST: both CMK tables work before anything is broken ---------------
    for table in (target, control):
        ddb.put_item(TableName=table, Item=item)
        got = ddb.get_item(TableName=table, Key={'pk': item['pk']}, ConsistentRead=True).get('Item')
        assert got == item, f'{table}: round trip failed before the key was disabled: {got!r}'

    # --- break exactly one thing -------------------------------------------------------
    kms.disable_key(KeyId=target_id)
    # Registered right after the break so a failure below cannot leave the table unreadable.
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=target_id))
    state = kms.describe_key(KeyId=target_id)['KeyMetadata']['KeyState']
    assert state == 'Disabled', f'DisableKey left the key in {state!r}, expected Disabled'
    # TableStatus is not asserted: the table stays ACTIVE for well over 15 minutes after DisableKey
    # while its data plane already refuses, so INACCESSIBLE_ENCRYPTION_CREDENTIALS is timing.

    deadline = time.monotonic() + _REJECT_CEILING_S
    attempts = 0
    while True:
        attempts += 1
        try:
            ddb.get_item(TableName=target, Key={'pk': item['pk']}, ConsistentRead=True)
        except ClientError as exc:
            e = exc.response.get('Error', {})
            code, msg = e.get('Code'), e.get('Message', '')
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'GetItem on a table whose CMK is disabled kept SUCCEEDING for '
                f'{_REJECT_CEILING_S}s ({attempts} attempts): the disabled key was never consulted'
            )
        time.sleep(2)
    assert code == ERR, (
        f'GetItem on a table whose CMK is disabled must fail with {ERR!r}, got {code!r}: {msg!r}'
    )
    # The message embeds the Request ID of DynamoDB's own KMS call, which no value this check
    # controls can reproduce, so the text around it is asserted exactly.
    kms_prefix = (
        f'KMS key disabled error: com.amazonaws.services.kms.model.{KMS_CAUSE}: {target_arn} is '
        f'disabled. (Service: AWSKMS; Status Code: 400; Error Code: {KMS_CAUSE}; Request ID: '
    )
    assert msg.startswith(kms_prefix) and msg.endswith('; Proxy: null)'), (
        f'the rejection must name the KMS cause {KMS_CAUSE!r} as {kms_prefix!r}...: {msg!r}'
    )

    refused = {'pk': {'S': f'refused-{token}'}, 'v': {'S': 'must-not-persist'}}
    put_code, put_msg = _err(lambda: ddb.put_item(TableName=target, Item=refused))
    assert put_code == ERR, (
        f'PutItem on a table whose CMK is disabled must fail with {ERR!r}, got {put_code!r}: '
        f'{put_msg!r}'
    )
    assert put_msg.startswith(kms_prefix) and put_msg.endswith('; Proxy: null)'), (
        f'the rejection must name the KMS cause {KMS_CAUSE!r} as {kms_prefix!r}...: {put_msg!r}'
    )

    # --- control during the break: a table on a different enabled CMK is unaffected --
    probe = {'pk': {'S': f'during-{token}'}, 'v': {'S': 'control'}}
    ddb.put_item(TableName=control, Item=probe)
    got = ddb.get_item(TableName=control, Key={'pk': probe['pk']}, ConsistentRead=True).get('Item')
    assert got == probe, (
        f'disabling one CMK broke a table encrypted with a DIFFERENT, enabled CMK: {got!r}'
    )

    # --- repair the one broken thing: the refusal reverses, data at rest survived -----
    kms.enable_key(KeyId=target_id)
    deadline = time.monotonic() + _RESTORE_CEILING_S
    while True:
        try:
            ddb.get_item(TableName=target, Key={'pk': item['pk']}, ConsistentRead=True)
            break
        except ClientError as exc:
            e = exc.response.get('Error', {})
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f're-enabling the CMK did not restore GetItem within {_RESTORE_CEILING_S}s: '
                    f'{e.get("Code")!r}: {e.get("Message")!r}'
                ) from exc
        time.sleep(5)
    kept = ddb.get_item(TableName=target, Key={'pk': item['pk']}, ConsistentRead=True).get('Item')
    assert kept == item, f'the item written before the disable did not survive it: {kept!r}'
    absent = ddb.get_item(TableName=target, Key={'pk': refused['pk']},
                          ConsistentRead=True).get('Item')
    assert absent is None, f'a PutItem refused while the key was disabled persisted: {absent!r}'
    after = {'pk': {'S': f'after-{token}'}, 'v': {'S': 'restored'}}
    ddb.put_item(TableName=target, Item=after)
    got = ddb.get_item(TableName=target, Key={'pk': after['pk']}, ConsistentRead=True).get('Item')
    assert got == after, f'writes were not restored after EnableKey: {got!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
