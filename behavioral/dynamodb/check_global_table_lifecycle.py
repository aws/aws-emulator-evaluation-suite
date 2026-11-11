"""global-table-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-lifecycle"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']

_LEGACY_VERSION_MESSAGE = (
    "One or more parameter values were invalid: DynamoDB global tables version 2017.11.29 is not "
    "supported. We recommend using DynamoDB global tables version 2019.11.21, instead of version "
    "2017.11.29 (Legacy)."
)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message', '')
    raise AssertionError(f'expected a ClientError, but the call succeeded and returned {result!r}')


def _second_region(primary):
    """A region distinct from the primary, needed only as an arbitrary replica target for the
    modern global-table mechanism -- not a pinned/global-service literal."""
    return 'us-west-2' if primary != 'us-west-2' else 'us-east-1'


def _create_replica_with_retry(ddb, table_name, region, *, timeout_s=90, interval_s=5):
    """UpdateTable's ReplicaUpdates "Create" issued right as the source table reaches ACTIVE can
    transiently fail with an AccessDeniedException wrapping an "UnrecognizedClientException"/
    "security token" message while DynamoDB's cross-region replication setup settles -- retry for
    a bounded time rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{'Create': {'RegionName': region}}])
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            transient = code == 'AccessDeniedException' and 'security token' in str(exc).lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_table_if_present(ddb, name):
    """Fallback net for the bare table; _teardown normally deletes it first."""
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        err = exc.response.get('Error', {})
        if err.get('Code') == 'ResourceNotFoundException':
            return
        if err.get('Code') == 'ResourceInUseException' and 'being deleted' in err.get('Message', ''):
            return
        raise


def _teardown(ddb, name, region):
    """Remove the replica, wait until it is gone, then delete the table. DeleteTable refuses
    the table with ValidationException ("acted as a source region ...") or
    ResourceInUseException until the replica has actually disappeared."""
    deadline = time.monotonic() + 240.0
    while True:
        try:
            ddb.update_table(TableName=name, ReplicaUpdates=[{'Delete': {'RegionName': region}}])
            break
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    while True:
        try:
            replicas = ddb.describe_table(TableName=name)['Table'].get('Replicas') or []
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return
            raise
        if not replicas:
            try:
                ddb.delete_table(TableName=name)
                return
            except ClientError as exc:
                err = exc.response.get('Error', {})
                retryable = err.get('Code') == 'ResourceInUseException' or (
                    err.get('Code') == 'ValidationException' and 'acted as a source region' in err.get('Message', '')
                )
                if not retryable or time.monotonic() >= deadline:
                    raise
        elif time.monotonic() >= deadline:
            raise AssertionError(f'replica {region} of {name} still present after teardown wait: {replicas}')
        time.sleep(3.0)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a new table, CreateGlobalTable and an UpdateGlobalTable replica Create raise the version ValidationException,
    DescribeGlobalTable raises GlobalTableNotFoundException and ListGlobalTables omits it, each with exact messages;
    UpdateTable ReplicaUpdates then adds the second-region replica.
    """
    ddb = ctx.client('dynamodb')
    second_region = _second_region(ctx.region)

    t = ctx.unique_name('sim2real-behav-gt-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # 1) CreateGlobalTable: legacy control plane unconditionally rejects new
    # global-table creation on modern accounts. The message must be the version gate, not some
    # unrelated validation failure.
    create_code, create_message = _error_code_and_message(
        lambda: ddb.create_global_table(GlobalTableName=t, ReplicationGroup=[{'RegionName': ctx.region}])
    )
    assert create_code == 'ValidationException', f'expected ValidationException, got {create_code} ({create_message})'
    assert create_message == _LEGACY_VERSION_MESSAGE, (
        f'expected message {_LEGACY_VERSION_MESSAGE!r}, got {create_message!r}'
    )

    # 2) DescribeGlobalTable: nothing is tracked yet either.
    describe_code, describe_message = _error_code_and_message(lambda: ddb.describe_global_table(GlobalTableName=t))
    assert describe_code == 'GlobalTableNotFoundException', f'expected GlobalTableNotFoundException, got {describe_code}'
    expected_not_found = f"Global table not found: Global table with name: '{t}' does not exist."
    assert describe_message == expected_not_found, (
        f'expected message {expected_not_found!r}, got {describe_message!r}'
    )

    # 3) ListGlobalTables: this table name is not present.
    listed_before = ddb.list_global_tables()['GlobalTables']
    assert not any(gt['GlobalTableName'] == t for gt in listed_before), (
        f'expected {t} absent from ListGlobalTables, got {listed_before}'
    )

    # 4) UpdateGlobalTable: the legacy control plane rejects a replica Create with the same
    # version gate as CreateGlobalTable.
    update_code, update_message = _error_code_and_message(
        lambda: ddb.update_global_table(GlobalTableName=t, ReplicaUpdates=[{'Create': {'RegionName': second_region}}])
    )
    assert update_code == 'ValidationException', f'expected ValidationException, got {update_code}'
    assert update_message == _LEGACY_VERSION_MESSAGE, (
        f'expected message {_LEGACY_VERSION_MESSAGE!r}, got {update_message!r}'
    )

    # The MODERN mechanism is what actually creates a working global table:
    # UpdateTable's ReplicaUpdates. Confirm the resulting replication state is
    # visible via DescribeTable.
    _create_replica_with_retry(ddb, t, second_region)
    ctx.on_cleanup(lambda: _teardown(ddb, t, second_region))

    # Wait for the replica to settle to ACTIVE: a replica still CREATING refuses the
    # teardown's replica Delete with ResourceInUseException.
    table = _poll_until(
        lambda: ddb.describe_table(TableName=t)['Table'],
        lambda tbl: tbl['TableStatus'] == 'ACTIVE' and any(
            r['RegionName'] == second_region and r.get('ReplicaStatus') == 'ACTIVE'
            for r in tbl.get('Replicas', [])
        ),
        timeout_s=300,
        interval_s=5.0,
        description='replica ACTIVE via DescribeTable',
    )
    assert any(r['RegionName'] == second_region for r in table['Replicas']), (
        f'expected replica in {second_region} via DescribeTable, got {table["Replicas"]}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
