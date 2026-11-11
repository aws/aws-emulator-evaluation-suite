"""xsvc-dynamodb-1-pending-deletion-cmk-reads-and-writes-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-1-pending-deletion-cmk-reads-and-writes-rejected"
GROUP = 'sse_kms'
SERVICES = ['dynamodb', 'kms']

_KMS_TAGS = [{"TagKey": "sim2real", "TagValue": "dynamodb-sse-cmk"}]
_DDB_TAGS = [{"Key": "sim2real", "Value": "dynamodb-sse-cmk"}]

# Once the table key cache lapses, GetItem/PutItem/Scan on a table whose CMK is PendingDeletion fail
# ValidationException "KMS validation error: com.amazonaws.services.kms.model.KMSInvalidStateException:
# <key arn> ...": DynamoDB wraps the KMS cause.
ERR = 'ValidationException'
KMS_CAUSE = 'KMSInvalidStateException'
_REJECT_CEILING_S = 480
_RESTORE_CEILING_S = 180
_OK = '<ok>'


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises.

    A call that SUCCEEDS raises AssertionError: a write accepted while the key is pending deletion
    is the over-permissive failure this check exists to catch.
    """
    try:
        resp = fn()
    except ClientError as exc:
        e = exc.response.get('Error', {})
        return e.get('Code'), e.get('Message', '')
    raise AssertionError(f'expected a ClientError, but the call succeeded: {resp!r}')


def _get_outcome(ddb, table, key):
    """One GetItem: (Error.Code, Error.Message) if it is refused, ('<ok>', '') if it succeeds.

    '<ok>' is not an AWS error code, so no code assertion can be satisfied by a success.
    """
    try:
        ddb.get_item(TableName=table, Key=key, ConsistentRead=True)
    except ClientError as exc:
        e = exc.response.get('Error', {})
        return e.get('Code'), e.get('Message', '')
    return _OK, ''


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
    # KMS has no immediate delete: 7 days is the minimum PendingWindowInDays. A run that fails while
    # the key is still PendingDeletion gets KMSInvalidStateException here, the key already scheduled.
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
    """Scheduling deletion of a table's customer-managed KMS key makes GetItem and PutItem fail with
    ValidationException naming KMSInvalidStateException while a table on another CMK keeps working;
    CancelKeyDeletion + EnableKey restores reads and writes with the earlier item intact.
    """
    kms = ctx.client('kms')
    ddb = ctx.client('dynamodb')
    token = uuid.uuid4().hex[:8]
    item = {'pk': {'S': f'kept-{token}'}, 'v': {'S': f'written-before-schedule|日本語-{token}'}}

    target_id, target_arn = _cmk(ctx, kms, 'pending-target')
    _, control_arn = _cmk(ctx, kms, 'pending-control')
    target = _cmk_table(ctx, ddb, target_arn)
    control = _cmk_table(ctx, ddb, control_arn)
    for table, arn in ((target, target_arn), (control, control_arn)):
        sse = _wait_active(ddb, table).get('SSEDescription') or {}
        assert sse.get('KMSMasterKeyArn') == arn, (
            f'{table} is not encrypted with the CMK this check created: {sse!r}, expected {arn!r}'
        )

    # --- control FIRST: both CMK tables work before anything is broken ---------------
    for table in (target, control):
        ddb.put_item(TableName=table, Item=item)
        got = ddb.get_item(TableName=table, Key={'pk': item['pk']}, ConsistentRead=True).get('Item')
        assert got == item, f'{table}: round trip failed before the key was scheduled: {got!r}'

    # --- break exactly one thing -------------------------------------------------------
    sched = kms.schedule_key_deletion(KeyId=target_id, PendingWindowInDays=7)
    assert sched['KeyState'] == 'PendingDeletion', (
        f'ScheduleKeyDeletion left the key in {sched["KeyState"]!r}, expected PendingDeletion'
    )

    # Polled because the table's cached data key lapses only minutes later. TableStatus is not
    # asserted: it turns INACCESSIBLE_ENCRYPTION_CREDENTIALS far later and recovers far later
    # than reads do, so either value would grade timing, not contract.
    deadline = time.monotonic() + _REJECT_CEILING_S
    attempts = 0
    while True:
        attempts += 1
        code, msg = _get_outcome(ddb, target, {'pk': item['pk']})
        if code != _OK or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert code == ERR, (
        f'GetItem on a table whose CMK is pending deletion must fail with {ERR!r} within '
        f'{_REJECT_CEILING_S}s ({attempts} attempts), got {code!r}: {msg!r} ({_OK!r} means the read '
        f'SUCCEEDED)'
    )
    # DynamoDB wraps the KMS KMSInvalidStateException text, which embeds KMS's own per-call
    # Request ID, so the text around it is asserted exactly.
    kms_prefix = (
        f'KMS validation error: com.amazonaws.services.kms.model.{KMS_CAUSE}: {target_arn} is '
        f'pending deletion. (Service: AWSKMS; Status Code: 400; Error Code: {KMS_CAUSE}; Request ID: '
    )
    assert msg.startswith(kms_prefix) and msg.endswith('; Proxy: null)'), (
        f'the rejection must name the KMS cause {KMS_CAUSE!r} as {kms_prefix!r}...: {msg!r}'
    )

    refused = {'pk': {'S': f'refused-{token}'}, 'v': {'S': 'must-not-persist'}}
    put_code, put_msg = _err(lambda: ddb.put_item(TableName=target, Item=refused))
    assert put_code == ERR, (
        f'PutItem on a table whose CMK is pending deletion must fail with {ERR!r}, got '
        f'{put_code!r}: {put_msg!r}'
    )
    # The same KMS-wrapped text with a per-call KMS Request ID.
    assert put_msg.startswith(kms_prefix) and put_msg.endswith('; Proxy: null)'), (
        f'the rejection must name the KMS cause {KMS_CAUSE!r} as {kms_prefix!r}...: {put_msg!r}'
    )

    # --- control during the break: a table on a different enabled CMK is unaffected --
    probe = {'pk': {'S': f'during-{token}'}, 'v': {'S': 'control'}}
    ddb.put_item(TableName=control, Item=probe)
    got = ddb.get_item(TableName=control, Key={'pk': probe['pk']}, ConsistentRead=True).get('Item')
    assert got == probe, (
        f'scheduling deletion of one CMK broke a table on a DIFFERENT, enabled CMK: {got!r}'
    )

    # --- repair: cancel the deletion (key lands Disabled), then enable it -------------
    kms.cancel_key_deletion(KeyId=target_id)
    # DescribeKey can report PendingDeletion for a moment after the cancel returns.
    left = ctx.time_left()
    state_deadline = time.monotonic() + (60.0 if left is None else min(60.0, left - 10.0))
    while True:
        state = kms.describe_key(KeyId=target_id)['KeyMetadata']['KeyState']
        if state != 'PendingDeletion' or time.monotonic() >= state_deadline:
            break
        time.sleep(2)
    assert state == 'Disabled', (
        f'CancelKeyDeletion must leave the key Disabled, not re-enable it: got {state!r}'
    )
    kms.enable_key(KeyId=target_id)
    deadline = time.monotonic() + _RESTORE_CEILING_S
    while True:
        rcode, rmsg = _get_outcome(ddb, target, {'pk': item['pk']})
        if rcode == _OK or time.monotonic() >= deadline:
            break
        time.sleep(5)
    assert rcode == _OK, (
        f'cancel + enable did not restore GetItem within {_RESTORE_CEILING_S}s: {rcode!r}: '
        f'{rmsg!r}'
    )
    kept = ddb.get_item(TableName=target, Key={'pk': item['pk']}, ConsistentRead=True).get('Item')
    assert kept == item, f'the item written before the schedule did not survive it: {kept!r}'
    absent = ddb.get_item(TableName=target, Key={'pk': refused['pk']},
                          ConsistentRead=True).get('Item')
    assert absent is None, f'a PutItem refused while the key was pending deletion persisted: {absent!r}'
    after = {'pk': {'S': f'after-{token}'}, 'v': {'S': 'restored'}}
    ddb.put_item(TableName=target, Item=after)
    got = ddb.get_item(TableName=target, Key={'pk': after['pk']}, ConsistentRead=True).get('Item')
    assert got == after, f'writes were not restored after cancel + enable: {got!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
