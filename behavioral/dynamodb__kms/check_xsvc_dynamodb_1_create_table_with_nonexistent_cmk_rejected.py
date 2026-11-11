"""xsvc-dynamodb-1-create-table-with-nonexistent-cmk-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-1-create-table-with-nonexistent-cmk-rejected"
GROUP = 'sse_kms'
SERVICES = ['dynamodb', 'kms']

_KMS_TAGS = [{"TagKey": "sim2real", "TagValue": "dynamodb-sse-cmk"}]
_DDB_TAGS = [{"Key": "sim2real", "Value": "dynamodb-sse-cmk"}]

# CreateTable naming a well-formed but nonexistent key ARN fails with ValidationException, message
# "KMS validation error: com.amazonaws.services.kms.model.NotFoundException: Key '<arn>' does not
# exist (... Request ID: <per-call id>; Proxy: null)", and no table is created.
ERR = 'ValidationException'
KMS_CAUSE = 'NotFoundException'


def _err(fn, on_success=None):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; raise if fn succeeds.

    on_success first receives the response so a wrongly-accepted create can register teardown.
    """
    try:
        resp = fn()
    except ClientError as exc:
        e = exc.response.get('Error', {})
        return e.get('Code'), e.get('Message', '')
    if on_success is not None:
        on_success(resp)
    raise AssertionError(f'expected a ClientError, but the call succeeded: {resp!r}')


def _wait_active(ddb, table, deadline_s=240):
    end = time.time() + deadline_s
    while time.time() < end:
        t = ddb.describe_table(TableName=table)['Table']
        if t['TableStatus'] == 'ACTIVE':
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never reached ACTIVE within {deadline_s}s')


def _create(ddb, table, key_ref):
    return ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        SSESpecification={'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': key_ref},
        Tags=_DDB_TAGS,
    )


@tags(
    "axis:rejection",
    "concern:e2e",
    "concern:negative-classes",
    "cap:c1",
    "plane:control",
)
def run(ctx) -> None:
    """CreateTable with SSE-KMS naming a nonexistent CMK ARN fails ValidationException (naming the
    KMS NotFoundException) and creates no table; the same create on a real CMK succeeds, so the
    refusal is about the key, not SSE-KMS creates in general.
    """
    kms = ctx.client('kms')
    ddb = ctx.client('dynamodb')
    ident = ctx.client('sts').get_caller_identity()
    account = ident['Account']
    partition = ident['Arn'].split(':')[1]
    missing_arn = f'arn:{partition}:kms:{ctx.region}:{account}:key/{uuid.uuid4()}'

    bad_table = ctx.unique_name('sim2real-xsvc-ddbkms-bad-')
    code, msg = _err(
        lambda: _create(ddb, bad_table, missing_arn),
        # The target wrongly accepted it: the table exists, so register its teardown before the
        # helper's assertion aborts the check.
        on_success=lambda _resp: ctx.on_cleanup(lambda: ddb.delete_table(TableName=bad_table)),
    )
    assert code == ERR, (
        f'CreateTable with nonexistent KMS key {missing_arn!r} must fail with {ERR!r}, got '
        f'{code!r}: {msg!r}'
    )
    # message varies: DynamoDB wraps the KMS NotFoundException text, which embeds KMS's own
    # per-call Request ID; the wrapped cause is the stable part.
    assert KMS_CAUSE in msg, f'the rejection must name the KMS cause {KMS_CAUSE!r}: {msg!r}'

    gone, gone_msg = _err(lambda: ddb.describe_table(TableName=bad_table))
    assert gone == 'ResourceNotFoundException', (
        f'a refused CreateTable must leave no table behind: DescribeTable gave {gone!r}: {gone_msg!r}'
    )
    expected_gone = f'Requested resource not found: Table: {bad_table} not found'
    assert gone_msg == expected_gone, (
        f'DescribeTable not-found message: {gone_msg!r}, expected {expected_gone!r}'
    )

    # --- positive control: the identical create on a real CMK succeeds ---------------
    key = kms.create_key(Description=f'sim2real-xsvc-ddb-sse-create-ctl-{uuid.uuid4().hex[:8]}',
                         KeyUsage='ENCRYPT_DECRYPT', Tags=_KMS_TAGS)['KeyMetadata']
    # KMS has no immediate delete: 7 days is the minimum PendingWindowInDays.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key['KeyId'], PendingWindowInDays=7))
    good_table = ctx.unique_name('sim2real-xsvc-ddbkms-ok-')
    _create(ddb, good_table, key['Arn'])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=good_table))
    sse = _wait_active(ddb, good_table).get('SSEDescription') or {}
    assert sse.get('KMSMasterKeyArn') == key['Arn'], (
        f'the control create did not land on the CMK it named: {sse!r}, expected {key["Arn"]!r}'
    )
    row = {'pk': {'S': 'control'}, 'v': {'S': 'ok'}}
    ddb.put_item(TableName=good_table, Item=row)
    got = ddb.get_item(TableName=good_table, Key={'pk': row['pk']}, ConsistentRead=True).get('Item')
    assert got == row, f'the control table did not round-trip an item: {got!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
