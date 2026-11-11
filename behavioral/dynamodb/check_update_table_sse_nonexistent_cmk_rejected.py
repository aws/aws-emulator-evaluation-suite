"""update-table-sse-nonexistent-cmk-rejected."""
from __future__ import annotations

import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-sse-nonexistent-cmk-rejected"
GROUP = 'sse_kms'
SERVICES = ['dynamodb']

# UpdateTable SSESpecification naming a well-formed but nonexistent key ARN fails with
# ValidationException, wrapping a KMS NotFoundException, and the table's own SSE is unchanged.
ERR = 'ValidationException'
KMS_CAUSE = 'NotFoundException'


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; raise if fn succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        e = exc.response.get('Error', {})
        return e.get('Code'), e.get('Message', '')
    raise AssertionError(f'expected a ClientError, but the call succeeded: {resp!r}')


def _wait_sse_settled(ddb, table, deadline_s=240):
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        t = ddb.describe_table(TableName=table)['Table']
        sse = t.get('SSEDescription') or {}
        if t['TableStatus'] == 'ACTIVE' and sse.get('Status') != 'UPDATING':
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never settled within {deadline_s}s')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable SSESpecification naming a nonexistent CMK ARN is rejected and leaves the
    table's own encryption settings unchanged; the identical call on a real CMK succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client('dynamodb')
    kms = ctx.client('kms')

    table = ctx.unique_name('sim2real-behav-ddb-sse-bad-cmk-')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})
    before = ddb.describe_table(TableName=table)['Table'].get('SSEDescription')
    assert before is None, f'expected a freshly created table to use the AWS owned key, got {before!r}'

    missing_arn = f'arn:aws:kms:{ctx.region}:{ctx.account}:key/{uuid.uuid4()}'

    code, msg = _err(
        lambda: ddb.update_table(
            TableName=table,
            SSESpecification={'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': missing_arn},
        )
    )
    assert code == ERR, (
        f'UpdateTable with nonexistent KMS key {missing_arn!r} must fail with {ERR!r}, got {code!r}: {msg!r}'
    )
    # The message wraps KMS's own NotFoundException text, which embeds a per-call KMS Request ID;
    # that id is masked and everything else is built from values this check knows.
    expected = (
        f"KMS validation error: com.amazonaws.services.kms.model.{KMS_CAUSE}: "
        f"Key '{missing_arn}' does not exist (Service: AWSKMS; Status Code: 400; "
        f"Error Code: {KMS_CAUSE}; Request ID: <request-id>; Proxy: null)"
    )
    assert re.sub(r'Request ID: [^;)]*', 'Request ID: <request-id>', msg) == expected, (
        f'expected message {expected!r} (request id masked), got {msg!r}'
    )

    after = ddb.describe_table(TableName=table)['Table']
    assert after['TableStatus'] == 'ACTIVE', (
        f'a refused UpdateTable must leave the table ACTIVE, got {after["TableStatus"]!r}'
    )
    assert after.get('SSEDescription') is None, (
        f'a refused UpdateTable must leave SSE unchanged (AWS owned key), got {after.get("SSEDescription")!r}'
    )

    # --- positive control: the identical update on a real CMK succeeds ---------------
    key = kms.create_key(
        Description=f'{table} control key', Tags=[{'TagKey': 'sim2real', 'TagValue': CHECK}],
    )['KeyMetadata']
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key['KeyId'], PendingWindowInDays=7))
    ddb.update_table(
        TableName=table,
        SSESpecification={'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': key['KeyId']},
    )
    settled = _wait_sse_settled(ddb, table).get('SSEDescription') or {}
    assert settled.get('Status') == 'ENABLED', f'expected the control update to settle ENABLED, got {settled!r}'
    assert settled.get('KMSMasterKeyArn') == key['Arn'], (
        f'expected the control update to land on {key["Arn"]!r}, got {settled.get("KMSMasterKeyArn")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
