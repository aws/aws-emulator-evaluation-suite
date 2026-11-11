"""update-table-vector-index-requires-pay-per-request."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-vector-index-requires-pay-per-request"
GROUP = 'vector'
SERVICES = ['dynamodb']

_NO_VECTOR_INDEX = ('ValidationException',
                    'One or more parameter values were invalid: Vector indexes are only '
                    'supported for PAY_PER_REQUEST tables')


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f'expected error code {code!r}, got {got_code!r} ({got_message!r})'
    assert got_message == message, f'expected message {message!r}, got {got_message!r}'


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table, deadline_s=240):
    deadline = time.monotonic() + deadline_s
    tbl = ddb.describe_table(TableName=table)['Table']
    while tbl['TableStatus'] != 'ACTIVE':
        assert time.monotonic() < deadline, f'{table} never became ACTIVE: {tbl!r}'
        time.sleep(2)
        tbl = ddb.describe_table(TableName=table)['Table']
    return tbl


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """UpdateTable refuses adding a vector index to a PROVISIONED table and refuses switching a
    table that already has a vector index to PROVISIONED; each leaves the table unchanged.
    """
    ddb = ctx.client('dynamodb')

    # A PROVISIONED table may not gain a vector index.
    provisioned = ctx.unique_name('sim2real-behav-ddbvecprov-')
    ddb.create_table(
        TableName=provisioned,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=provisioned),
                             'ResourceNotFoundException'))
    _wait_active(ddb, provisioned)

    expect_error(lambda: ddb.update_table(
        TableName=provisioned,
        VectorIndexUpdates=[{'Create': {
            'IndexName': 'idx',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 8,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }}],
    ), *_NO_VECTOR_INDEX)

    tbl = ddb.describe_table(TableName=provisioned)['Table']
    assert not tbl.get('VectorIndexes'), (
        f'the refused UpdateTable left a vector index on {provisioned}: {tbl.get("VectorIndexes")!r}'
    )
    assert tbl['ProvisionedThroughput']['ReadCapacityUnits'] == 1, (
        f'expected ReadCapacityUnits 1, got {tbl["ProvisionedThroughput"]!r}'
    )
    assert tbl['ProvisionedThroughput']['WriteCapacityUnits'] == 1, (
        f'expected WriteCapacityUnits 1, got {tbl["ProvisionedThroughput"]!r}'
    )

    # Positive control: the same table still accepts an ordinary UpdateTable.
    ddb.update_table(
        TableName=provisioned,
        ProvisionedThroughput={'ReadCapacityUnits': 2, 'WriteCapacityUnits': 2},
    )
    deadline = time.monotonic() + 240
    tbl = _wait_active(ddb, provisioned)
    while tbl['ProvisionedThroughput']['ReadCapacityUnits'] != 2:
        assert time.monotonic() < deadline, (
            f'the throughput bump never settled: {tbl["ProvisionedThroughput"]!r}'
        )
        time.sleep(2)
        tbl = _wait_active(ddb, provisioned)
    assert tbl['ProvisionedThroughput']['WriteCapacityUnits'] == 2, (
        f'expected WriteCapacityUnits 2 after the bump settled, got {tbl["ProvisionedThroughput"]!r}'
    )

    # A table that already carries a vector index may not switch to PROVISIONED.
    vectored = ctx.unique_name('sim2real-behav-ddbvecprov-')
    ddb.create_table(
        TableName=vectored,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx2',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 8,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=vectored),
                             'ResourceNotFoundException'))
    _wait_active(ddb, vectored)

    expect_error(lambda: ddb.update_table(
        TableName=vectored,
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
    ), *_NO_VECTOR_INDEX)

    tbl = ddb.describe_table(TableName=vectored)['Table']
    assert tbl['BillingModeSummary']['BillingMode'] == 'PAY_PER_REQUEST', (
        f'the refused UpdateTable switched billing mode: {tbl.get("BillingModeSummary")!r}'
    )
    assert [v['IndexName'] for v in tbl.get('VectorIndexes', [])] == ['idx2'], (
        f'the refused UpdateTable changed the vector indexes: {tbl.get("VectorIndexes")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
