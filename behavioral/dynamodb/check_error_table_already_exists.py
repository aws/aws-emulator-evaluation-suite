"""error-table-already-exists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-table-already-exists"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_RESOURCE_IN_USE = 'ResourceInUseException'
ERR_RESOURCE_NOT_FOUND = 'ResourceNotFoundException'


def _key_schema():
    return {
        'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
        'BillingMode': 'PAY_PER_REQUEST',
    }


def _client_error(fn):
    """Call fn(); return its botocore Error Code and Message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected a ClientError, but the call SUCCEEDED and returned {result!r}')


def _wait_gone(ddb, table, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == ERR_RESOURCE_NOT_FOUND:
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f'table {table!r} never became fully deleted')


def _safe_delete(ddb, table):
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != ERR_RESOURCE_NOT_FOUND:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable with an existing name raises ResourceInUseException with the exact message and leaves the table
    ACTIVE with its TableId; once that table is deleted, the name creates a new table with a new TableId.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')

    # Positive control: the first create succeeds and the table becomes ACTIVE.
    ddb.create_table(TableName=table, **_key_schema())
    ctx.on_cleanup(lambda: _safe_delete(ddb, table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    original_id = ddb.describe_table(TableName=table)['Table']['TableId']

    # Break exactly one thing: create the SAME name again while it still exists.
    code, message = _client_error(lambda: ddb.create_table(TableName=table, **_key_schema()))
    assert code == ERR_RESOURCE_IN_USE, f'expected {ERR_RESOURCE_IN_USE}, got {code!r}'
    assert message == f"Table already exists: {table}", (
        f"expected the exact ResourceInUseException message AWS returns, got {message!r}"
    )

    # Effect absent, via an independent read: the rejected attempt did not replace or
    # otherwise disturb the existing table: TableId must be unchanged.
    after_reject = ddb.describe_table(TableName=table)['Table']
    assert after_reject['TableId'] == original_id, (
        f'existing table was disturbed by the rejected duplicate create: '
        f'expected TableId {original_id!r}, got {after_reject["TableId"]!r}'
    )
    assert after_reject['TableStatus'] == 'ACTIVE', (
        f'existing table left ACTIVE, got {after_reject["TableStatus"]!r}'
    )

    # Restore: delete the table for real, and prove the name is gone via an independent read.
    ddb.delete_table(TableName=table)
    _wait_gone(ddb, table)

    # The identical call now succeeds: the conflict tracked live existence, not the name.
    ddb.create_table(TableName=table, **_key_schema())
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    recreated_id = ddb.describe_table(TableName=table)['Table']['TableId']
    assert recreated_id != original_id, (
        f'recreated table kept the deleted table\'s identity ({recreated_id!r})'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
